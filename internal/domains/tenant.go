package domains

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/sysuser"
)

// sysNameRe mirrors the web layer's usernameRe: anything recorded as a system
// user is written verbatim into a root-generated php-fpm pool file, so every
// derived candidate must re-pass the same injection guard.
var sysNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// deriveSystemUser picks a Linux account name for an owner from their panel
// username: the username itself, then suffixed variants (name-2, name-3, …),
// deterministically truncating the base so a candidate never exceeds 32 chars.
// taken reports names that must be skipped (reserved, referenced by another
// panel account, or already existing on the OS — auto-provisioning must never
// silently adopt an account it did not create).
func deriveSystemUser(base string, taken func(string) bool) (string, error) {
	base = strings.ToLower(strings.TrimSpace(base))
	if !sysNameRe.MatchString(base) {
		return "", fmt.Errorf("cannot derive a system user from username %q", base)
	}
	for i := 1; i <= 100; i++ {
		cand := base
		if i > 1 {
			suffix := "-" + strconv.Itoa(i)
			b := base
			if len(b)+len(suffix) > 32 {
				b = b[:32-len(suffix)]
			}
			cand = b + suffix
		}
		if !sysNameRe.MatchString(cand) {
			continue
		}
		if !taken(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("could not find a free system user name for %q", base)
}

// ensureTenant guarantees the owner account has a Linux system user, creating
// and recording one just-in-time when missing (so "this account has no system
// user" stops being a dead end — the bootstrap admin never gets one at
// first-run). owner is mutated in place on success. The returned warning is
// non-fatal advice for the operator (e.g. a partially-failed upgrade of the
// owner's pre-existing sites); the primary operation should proceed on it.
func (s *Service) ensureTenant(ctx context.Context, owner *store.User) (warning string, err error) {
	if owner.SystemUser != "" {
		return "", nil
	}
	// Serialize derive→create→persist: two concurrent calls could otherwise both
	// see a candidate as free and the second would silently adopt the first's
	// freshly-created account.
	s.tenantMu.Lock()
	defer s.tenantMu.Unlock()

	// Re-read under the lock — another request may have provisioned meanwhile.
	fresh, ferr := s.store.UserByID(owner.ID)
	if ferr != nil {
		return "", ferr
	}
	if fresh.SystemUser != "" {
		owner.SystemUser = fresh.SystemUser
		return "", nil
	}

	name, derr := deriveSystemUser(owner.Username, func(c string) bool {
		if sysuser.IsReserved(c) {
			return true
		}
		if n, cerr := s.store.CountBySystemUser(c); cerr != nil || n > 0 {
			return true // referenced by another account (or unknowable — skip)
		}
		return s.sysuser.Exists(c) // never adopt a pre-existing OS account
	})
	if derr != nil {
		return "", derr
	}
	if err := s.sysuser.Ensure(ctx, name); err != nil {
		return "", err
	}
	// Persist BEFORE the upgrade pass: if anything below fails, a retry must
	// find SystemUser set rather than re-deriving and orphaning this account.
	if err := s.store.UpdateUserSystemUser(owner.ID, name); err != nil {
		return "", err
	}
	owner.SystemUser = name
	log.Printf("provisioned system user %q for account %q", name, owner.Username)
	return s.upgradeOwnerSites(ctx, owner), nil
}

// upgradeOwnerSites migrates an owner's PRE-EXISTING sites onto their newly
// provisioned system user: re-owning each site's canonical directory tree and
// regenerating its php-fpm pool (which previously ran as the web-server user).
// Best-effort per site — a partial failure is reported as a warning naming the
// repair action, never as a failure of the operation that triggered it.
func (s *Service) upgradeOwnerSites(ctx context.Context, owner *store.User) string {
	sites, err := s.store.ListSitesByUser(owner.ID)
	if err != nil || len(sites) == 0 {
		return ""
	}
	// Pool files + cfg.WebServer are shared with server switches and adoption.
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	var failed []string
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue // imported sites are read-only until adopted
		}
		// Re-own ONLY the site's own canonical /var/www/<domain> subtree. An
		// admin-created custom doc root may point anywhere under the web root —
		// possibly into ANOTHER tenant's tree — and must never be re-owned here.
		own := filepath.Join(s.cfg.WebRoot, site.Domain)
		if !s.cfg.Dev && pathWithin(own, site.DocRoot) {
			s.chown(own, owner.SystemUser)
		}
		if err := s.reprovisionPHP(ctx, site); err != nil {
			log.Printf("upgrade site %s to system user %s: %v", site.Domain, owner.SystemUser, err)
			failed = append(failed, site.Domain)
		}
	}
	if len(failed) > 0 {
		return "some existing sites could not be switched to the new system user (" +
			strings.Join(failed, ", ") + ") — use Settings → Regenerate site configs to repair"
	}
	return ""
}
