package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seedProject creates a user + main site and returns their IDs.
func seedProject(t *testing.T, s *Store) (userID, siteID int64) {
	t.Helper()
	u, err := s.CreateUser(&User{Username: "alice", PasswordHash: "x", Role: RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	site, err := s.CreateSite(&Site{UserID: u.ID, Domain: "example.com", Type: SiteMain, DocRoot: "/var/www/example.com/public_html"})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, site.ID
}

// The Ship C migration retires unmanaged proxy apps and turns the legacy port
// column into an inert site_id mirror. It must: convert an unmanaged app that
// has a start command to managed; drop an unmanaged app with no command and
// revert its site to files; and align every app's port with its site_id.
func TestShipCAppMigration(t *testing.T) {
	s := openTemp(t)
	u, _ := seedProject(t, s)

	mk := func(domain string) int64 {
		site, err := s.CreateSite(&Site{UserID: u, Domain: domain, Type: SiteMain, DocRoot: "/var/www/" + domain, WebMode: WebModeProxy})
		if err != nil {
			t.Fatal(err)
		}
		return site.ID
	}
	withCmd := mk("withcmd.com")    // unmanaged + command -> becomes managed
	noCmd := mk("nocmd.com")        // unmanaged + no command -> dropped, site -> php
	alreadyMgd := mk("managed.com") // already managed -> port realigned

	// Insert legacy rows directly (CreateApp now forces managed + port=site_id),
	// using stale ports from the retired 3000-3999 range.
	for _, r := range []struct {
		siteID  int64
		port    int
		cmd     string
		managed int
	}{
		{withCmd, 3000, "node server.js", 0},
		{noCmd, 3001, "", 0},
		{alreadyMgd, 3002, "npm start", 1},
	} {
		if _, err := s.db.Exec(`INSERT INTO apps (site_id, port, runtime, start_command, managed, env, last_status, created_at) VALUES (?,?,'node',?,?,'','',0)`,
			r.siteID, r.port, r.cmd, r.managed); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.migrate(); err != nil { // idempotent re-run applies the migration
		t.Fatalf("migrate: %v", err)
	}

	// withCmd: converted to managed, port aligned to its site_id.
	if app, err := s.AppBySite(withCmd); err != nil {
		t.Fatalf("withCmd app should survive: %v", err)
	} else if !app.Managed || app.Port != int(withCmd) {
		t.Errorf("withCmd: managed=%v port=%d, want managed=true port=%d", app.Managed, app.Port, withCmd)
	}
	// noCmd: app dropped, site reverted to files.
	if _, err := s.AppBySite(noCmd); err == nil {
		t.Error("noCmd app should have been deleted")
	}
	if site, err := s.SiteByID(noCmd); err != nil || site.WebMode != WebModePHP {
		t.Errorf("noCmd site web_mode=%q, want php", site.WebMode)
	}
	// alreadyMgd: stays managed, port realigned to site_id.
	if app, err := s.AppBySite(alreadyMgd); err != nil || app.Port != int(alreadyMgd) {
		t.Errorf("alreadyMgd port=%d, want %d", app.Port, alreadyMgd)
	}
}

func TestRepoRoundtripPreservesWebhookAndNote(t *testing.T) {
	s := openTemp(t)
	_, siteID := seedProject(t, s)

	created, err := s.CreateRepo(&Repo{
		ProjectSiteID: siteID, Owner: "acme", Name: "shop",
		URL: "https://github.com/acme/shop.git", AuthMode: "deploy_key",
		Branch: "main", CheckoutDir: "/var/www/example.com/repo",
		WebhookSecret: "aabbccddeeff00112233445566778899",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.RepoByID(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebhookSecret != "aabbccddeeff00112233445566778899" {
		t.Errorf("webhook secret lost in roundtrip: %q", got.WebhookSecret)
	}
	if err := s.SetRepoDetectNote(created.ID, "needs a build step"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRepoBranch(created.ID, "develop"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.RepoByID(created.ID)
	if got.DetectNote != "needs a build step" || got.Branch != "develop" {
		t.Errorf("note/branch not persisted: %q %q", got.DetectNote, got.Branch)
	}
}

func TestUpdateUserSystemUser(t *testing.T) {
	s := openTemp(t)
	userID, _ := seedProject(t, s)
	if err := s.UpdateUserSystemUser(userID, "alice"); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByID(userID)
	if err != nil || u.SystemUser != "alice" {
		t.Fatalf("system user not persisted: %+v, %v", u, err)
	}
	if n, _ := s.CountBySystemUser("alice"); n != 1 {
		t.Errorf("CountBySystemUser = %d, want 1", n)
	}
}

// A busy status found at startup was orphaned by a restart mid-job; the sweep
// must flip it to a retryable error and leave settled repos untouched.
func TestResetStaleRepoDeploys(t *testing.T) {
	s := openTemp(t)
	_, siteID := seedProject(t, s)
	repo, err := s.CreateRepo(&Repo{ProjectSiteID: siteID, Owner: "a", Name: "b", URL: "u", CheckoutDir: "/x", LastStatus: "cloning"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetStaleRepoDeploys(); err != nil {
		t.Fatal(err)
	}
	got, _ := s.RepoByID(repo.ID)
	if got.LastStatus != "error" || got.LastError == "" {
		t.Errorf("stale busy repo not reset: %q %q", got.LastStatus, got.LastError)
	}
	// A settled repo must not be touched.
	_ = s.UpdateRepoDeploy(repo.ID, "abc123", "ok", "", got.CreatedAt)
	_ = s.ResetStaleRepoDeploys()
	got, _ = s.RepoByID(repo.ID)
	if got.LastStatus != "ok" || got.LastCommit != "abc123" {
		t.Errorf("settled repo was clobbered: %+v", got)
	}
}

// Unlink must detach site mappings (repo_id/repo_subdir) while leaving the
// doc root and mode serving as-is.
func TestClearRepoMapping(t *testing.T) {
	s := openTemp(t)
	_, siteID := seedProject(t, s)
	repo, err := s.CreateRepo(&Repo{ProjectSiteID: siteID, Owner: "a", Name: "b", URL: "u", CheckoutDir: "/var/www/example.com/repo"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSiteMapping(siteID, sql.NullInt64{Int64: repo.ID, Valid: true}, "public", "", "composer install", "/var/www/example.com/repo/public", WebModePHP); err != nil {
		t.Fatal(err)
	}
	// The mapping round-trips the new build column.
	if site, err := s.SiteByID(siteID); err != nil || site.BuildCommand != "composer install" {
		t.Fatalf("mapping did not persist build_command: %+v err=%v", site, err)
	}
	if err := s.ClearRepoMapping(repo.ID); err != nil {
		t.Fatal(err)
	}
	site, err := s.SiteByID(siteID)
	if err != nil {
		t.Fatal(err)
	}
	if site.RepoID.Valid || site.RepoSubdir != "" || site.BuildCommand != "" || site.PublishDir != "" {
		t.Errorf("mapping not cleared: %+v", site)
	}
	if site.DocRoot != "/var/www/example.com/repo/public" || site.WebMode != WebModePHP {
		t.Errorf("doc root/mode must survive an unlink: %+v", site)
	}
}
