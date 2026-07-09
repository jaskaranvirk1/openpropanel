// Package deploy clones and updates GitHub repositories for a project, entirely
// from the panel. It generates a per-repo ed25519 deploy key, verifies the
// github.com host key against a pinned known_hosts, and runs every git command
// as the project's tenant system user (NEVER as root) so a tenant-owned
// checkout cannot use git hooks or core.sshCommand to execute as root.
//
// Auth modes (auto-selected by the caller): https_public (no key), deploy_key
// (per-repo key the operator adds to the repo once), or pat (a one-time token
// used to register the key via the GitHub API). Only the PUBLIC half of the key
// is ever stored/shown; the private half stays 0600 under the root-owned data
// dir and is copied to a short-lived, tenant-readable temp file only for the
// duration of a single git call.
package deploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/system"
	"golang.org/x/crypto/ssh"
)

// pinnedKnownHosts are github.com's published SSH host keys (ed25519, ecdsa,
// rsa). Pinning them lets us use StrictHostKeyChecking=yes without a TOFU
// prompt. If GitHub rotates a key, this is refreshed in a release.
const pinnedKnownHosts = `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4Zvfr9d3glc=
`

// Auth modes.
const (
	AuthDeployKey = "deploy_key"
	AuthPAT       = "pat"
	AuthPublic    = "https_public"
)

var (
	repoPartRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	branchRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
)

// Manager performs deploy operations.
type Manager struct{ cfg *config.Config }

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// ParseGitHubURL validates and canonicalises a GitHub repo reference (accepting
// SSH, HTTPS, or "owner/repo" forms) into its owner and name. The strict
// charset means owner/name can be safely reused to reconstruct URLs — raw user
// text never reaches a git command line.
func ParseGitHubURL(raw string) (owner, name string, err error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".git")
	for _, p := range []string{"git@github.com:", "ssh://git@github.com/", "https://github.com/", "http://github.com/"} {
		if strings.HasPrefix(s, p) {
			s = strings.TrimPrefix(s, p)
			break
		}
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) != 2 {
		return "", "", errors.New("enter a GitHub repository like https://github.com/owner/repo")
	}
	owner, name = parts[0], parts[1]
	if !repoPartRe.MatchString(owner) || !repoPartRe.MatchString(name) {
		return "", "", errors.New("invalid repository owner or name")
	}
	return owner, name, nil
}

// ValidBranch reports whether a branch name is safe to pass to git.
func ValidBranch(b string) bool { return branchRe.MatchString(b) }

// SSHURL / HTTPSURL rebuild canonical clone URLs from validated parts.
func SSHURL(owner, name string) string   { return "git@github.com:" + owner + "/" + name + ".git" }
func HTTPSURL(owner, name string) string { return "https://github.com/" + owner + "/" + name + ".git" }

func (m *Manager) deployRoot() string  { return filepath.Join(m.cfg.DataDir, "deploy") }
func (m *Manager) keyDir(id int64) string { return filepath.Join(m.deployRoot(), strconv.FormatInt(id, 10)) }
func (m *Manager) keyPath(id int64) string { return filepath.Join(m.keyDir(id), "id_ed25519") }

// GenerateKey creates a per-repo ed25519 deploy key. The private half is written
// 0600 under the root-owned data dir; the returned public line is safe to store
// and show for pasting into the repo's GitHub Deploy Keys.
func (m *Manager) GenerateKey(repoID int64) (publicLine, fingerprint string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "openpropanel-deploy")
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(m.keyDir(repoID), 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(m.keyPath(repoID), pem.EncodeToMemory(block), 0o600); err != nil {
		return "", "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " openpropanel-deploy"
	return line, ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// RemoveKey deletes a repo's key material.
func (m *Manager) RemoveKey(repoID int64) { _ = os.RemoveAll(m.keyDir(repoID)) }

// IsPublic reports whether a GitHub repo is public (an unauthenticated API 200
// with "private":false), so a public repo can be cloned over HTTPS with no key.
func (m *Manager) IsPublic(ctx context.Context, owner, name string) bool {
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, "https://api.github.com/repos/"+owner+"/"+name, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return strings.Contains(string(b), `"private":false`)
}

// ensureKnownHosts writes the pinned host keys to the data dir once.
func (m *Manager) ensureKnownHosts() (string, error) {
	if err := os.MkdirAll(m.deployRoot(), 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(m.deployRoot(), "known_hosts")
	if _, err := os.Stat(p); err != nil {
		if werr := os.WriteFile(p, []byte(pinnedKnownHosts), 0o644); werr != nil {
			return "", werr
		}
	}
	return p, nil
}

// tenantKey copies a repo's private key to a short-lived temp file readable by
// the tenant uid, returning its path and a cleanup func. Used only for the
// lifetime of one git call.
func (m *Manager) tenantKey(repoID int64, uid, gid uint32) (string, func(), error) {
	b, err := os.ReadFile(m.keyPath(repoID))
	if err != nil {
		return "", nil, fmt.Errorf("deploy key missing (regenerate it): %w", err)
	}
	dir, err := os.MkdirTemp("", "opp-deploy-")
	if err != nil {
		return "", nil, err
	}
	kp := filepath.Join(dir, "key")
	if err := os.WriteFile(kp, b, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	_ = os.Chown(kp, int(uid), int(gid))
	_ = os.Chown(dir, int(uid), int(gid))
	return kp, func() { _ = os.RemoveAll(dir) }, nil
}

// gitEnv builds a hardened environment for a git-over-ssh call.
func (m *Manager) gitEnv(keyPath, knownHosts string) []string {
	ssh := "ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15 -o UserKnownHostsFile=" + shellQuote(knownHosts)
	if keyPath != "" {
		ssh += " -i " + shellQuote(keyPath)
	}
	// Build from a small allowlist rather than the panel's full (root) process
	// environment: the git child runs as the tenant uid, so anything we pass is
	// readable by the tenant. Carry only what git/ssh need to function; drop
	// everything else so no operator-injected variable can leak across.
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/true",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_SSH_COMMAND=" + ssh,
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "HOME=") ||
			strings.HasPrefix(kv, "LANG=") || strings.HasPrefix(kv, "LC_") ||
			strings.HasPrefix(kv, "TERM=") {
			env = append(env, kv)
		}
	}
	return env
}

// runGit runs git as the tenant with hardening flags and (for SSH modes) the
// repo's deploy key.
func (m *Manager) runGit(ctx context.Context, r *store.Repo, uid, gid uint32, dir string, args ...string) (string, error) {
	known, err := m.ensureKnownHosts()
	if err != nil {
		return "", err
	}
	keyPath := ""
	if r.AuthMode != AuthPublic {
		kp, cleanup, kerr := m.tenantKey(r.ID, uid, gid)
		if kerr != nil {
			return "", kerr
		}
		defer cleanup()
		keyPath = kp
	}
	full := []string{"-c", "credential.helper=", "-c", "protocol.ext.allow=never"}
	if dir != "" {
		full = append([]string{"-C", dir}, full...)
	}
	full = append(full, args...)
	return system.RunAs(ctx, uid, gid, m.gitEnv(keyPath, known), "git", full...)
}

// cloneURL is the SSH url for key/pat modes, HTTPS for public.
func cloneURL(r *store.Repo) string {
	if r.AuthMode == AuthPublic {
		return HTTPSURL(r.Owner, r.Name)
	}
	return SSHURL(r.Owner, r.Name)
}

// Verify tests connectivity/authorisation with `git ls-remote` (no checkout).
func (m *Manager) Verify(ctx context.Context, r *store.Repo, uid, gid uint32) error {
	if m.cfg.Dev {
		return nil
	}
	if !ValidBranch(r.Branch) {
		return errors.New("invalid branch name")
	}
	_, err := m.runGit(ctx, r, uid, gid, "", "ls-remote", "--heads", cloneURL(r))
	return err
}

// Clone performs a fresh single-branch checkout into r.CheckoutDir (owned by the
// tenant). A pre-existing checkout dir is removed first.
func (m *Manager) Clone(ctx context.Context, r *store.Repo, uid, gid uint32) error {
	if m.cfg.Dev {
		return os.MkdirAll(r.CheckoutDir, 0o755)
	}
	if !ValidBranch(r.Branch) {
		return errors.New("invalid branch name")
	}
	// Clone starts from a clean directory, so a pre-existing checkout is removed
	// first. Guard against destroying real content: only remove the target if it
	// is empty or is itself a git checkout (safe to re-create). Refuse to
	// os.RemoveAll a non-empty directory we did not create — e.g. a doc root a
	// tenant filled with their own files that happens to collide with this path.
	if fi, err := os.Stat(r.CheckoutDir); err == nil && fi.IsDir() {
		if !dirEmpty(r.CheckoutDir) && !isGitCheckout(r.CheckoutDir) {
			return fmt.Errorf("refusing to overwrite %s: it is not empty and is not a git checkout — move its contents aside first", r.CheckoutDir)
		}
	}
	if err := os.MkdirAll(filepath.Dir(r.CheckoutDir), 0o755); err != nil {
		return err
	}
	_ = os.Chown(filepath.Dir(r.CheckoutDir), int(uid), int(gid))
	_ = os.RemoveAll(r.CheckoutDir)
	_, err := m.runGit(ctx, r, uid, gid, "",
		"clone", "--branch", r.Branch, "--single-branch", "--depth", "1", cloneURL(r), r.CheckoutDir)
	return err
}

// isGitCheckout reports whether dir looks like a git working tree (has a .git).
func isGitCheckout(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// dirEmpty reports whether dir has no entries. A dir it cannot read is treated
// as non-empty (fail safe — do not delete what we cannot inspect).
func dirEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == io.EOF
}

// Deploy fetches and hard-resets an existing checkout to origin/<branch>,
// returning the new short commit hash.
func (m *Manager) Deploy(ctx context.Context, r *store.Repo, uid, gid uint32) (string, error) {
	if m.cfg.Dev {
		return "devcommit", nil
	}
	if !ValidBranch(r.Branch) {
		return "", errors.New("invalid branch name")
	}
	if _, err := m.runGit(ctx, r, uid, gid, r.CheckoutDir, "fetch", "--prune", "--depth", "1", "origin", r.Branch); err != nil {
		return "", err
	}
	if _, err := m.runGit(ctx, r, uid, gid, r.CheckoutDir, "reset", "--hard", "origin/"+r.Branch); err != nil {
		return "", err
	}
	out, err := m.runGit(ctx, r, uid, gid, r.CheckoutDir, "rev-parse", "--short", "HEAD")
	return strings.TrimSpace(out), err
}

// shellQuote single-quotes a path for embedding in GIT_SSH_COMMAND.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
