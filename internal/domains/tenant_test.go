package domains

import (
	"strings"
	"testing"
)

func TestDeriveSystemUserPrefersBase(t *testing.T) {
	got, err := deriveSystemUser("alice", func(string) bool { return false })
	if err != nil || got != "alice" {
		t.Fatalf("deriveSystemUser = %q, %v; want alice", got, err)
	}
}

func TestDeriveSystemUserSuffixesOnCollision(t *testing.T) {
	taken := map[string]bool{"alice": true, "alice-2": true}
	got, err := deriveSystemUser("alice", func(c string) bool { return taken[c] })
	if err != nil || got != "alice-3" {
		t.Fatalf("deriveSystemUser = %q, %v; want alice-3", got, err)
	}
}

// A 32-char username + suffix must truncate the BASE deterministically and
// still satisfy the pool-file injection regex.
func TestDeriveSystemUserTruncatesLongBase(t *testing.T) {
	base := strings.Repeat("a", 32)
	got, err := deriveSystemUser(base, func(c string) bool { return c == base })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 32 {
		t.Errorf("candidate %q exceeds 32 chars", got)
	}
	if !sysNameRe.MatchString(got) {
		t.Errorf("candidate %q fails the system-user regex", got)
	}
	if want := strings.Repeat("a", 30) + "-2"; got != want {
		t.Errorf("deriveSystemUser = %q, want %q", got, want)
	}
}

func TestDeriveSystemUserExhaustionAndBadBase(t *testing.T) {
	if _, err := deriveSystemUser("alice", func(string) bool { return true }); err == nil {
		t.Error("all-taken should error, not loop")
	}
	if _, err := deriveSystemUser("Bad Name!", func(string) bool { return false }); err == nil {
		t.Error("an invalid base must be rejected")
	}
	if _, err := deriveSystemUser("ab", func(string) bool { return false }); err == nil {
		t.Error("a too-short base must be rejected")
	}
}
