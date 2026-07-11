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
	if err := s.SetSiteMapping(siteID, sql.NullInt64{Int64: repo.ID, Valid: true}, "public", "/var/www/example.com/repo/public", WebModePHP); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearRepoMapping(repo.ID); err != nil {
		t.Fatal(err)
	}
	site, err := s.SiteByID(siteID)
	if err != nil {
		t.Fatal(err)
	}
	if site.RepoID.Valid || site.RepoSubdir != "" {
		t.Errorf("mapping not cleared: %+v", site)
	}
	if site.DocRoot != "/var/www/example.com/repo/public" || site.WebMode != WebModePHP {
		t.Errorf("doc root/mode must survive an unlink: %+v", site)
	}
}
