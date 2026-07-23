package cron

import "testing"

// Schedule fields must be single cron tokens — no spaces or newlines that could
// shift columns or inject an extra crontab line.
func TestValidField(t *testing.T) {
	ok := []string{"*", "*/5", "0", "0-30", "1,15,30", "1-5/2", "mon", "JAN", "*/15"}
	for _, f := range ok {
		if !ValidField(f) {
			t.Errorf("ValidField(%q) = false, want true", f)
		}
	}
	// Includes tokens the old char-class regex wrongly accepted but crond rejects:
	// step-zero, incomplete ranges, and empty list elements.
	bad := []string{"", "1 2", "* *", "5\n0 0 * * *", "a;b", "$(x)", "`x`", "*/5 ", "*/0", "7-", "-7", "1,", ",1", "1--5", "/5"}
	for _, f := range bad {
		if ValidField(f) {
			t.Errorf("ValidField(%q) = true, want false", f)
		}
	}
}

// A command must be exactly one line; newlines would inject crontab lines.
func TestCleanCommand(t *testing.T) {
	if _, err := CleanCommand("  "); err == nil {
		t.Error("empty command should error")
	}
	if _, err := CleanCommand("echo hi\n0 0 * * * rm -rf /"); err == nil {
		t.Error("newline in command should error (line injection)")
	}
	if _, err := CleanCommand("echo\x00hi"); err == nil {
		t.Error("NUL in command should error")
	}
	got, err := CleanCommand("  /usr/bin/php cron.php >/dev/null 2>&1  ")
	if err != nil || got != "/usr/bin/php cron.php >/dev/null 2>&1" {
		t.Errorf("CleanCommand trimmed = %q, err=%v", got, err)
	}
}

func TestJobLine(t *testing.T) {
	j := Job{Minute: "*/5", Hour: "*", Dom: "*", Month: "*", Dow: "*", Command: "echo hi"}
	if got, want := j.Line(), "*/5 * * * * echo hi"; got != want {
		t.Errorf("Line() = %q, want %q", got, want)
	}
}

// stripManagedBlock removes only our BEGIN..END block, keeping hand-added lines.
func TestStripManagedBlock(t *testing.T) {
	crontab := "MAILTO=me@x.com\n@reboot /home/u/boot.sh\n" +
		beginMarker + "\n*/5 * * * * /panel/job1\n0 0 * * * /panel/job2\n" + endMarker + "\n" +
		"# my own note\n30 3 * * * /home/u/backup.sh\n"
	got := stripManagedBlock(crontab)
	for _, keep := range []string{"MAILTO=me@x.com", "@reboot /home/u/boot.sh", "# my own note", "/home/u/backup.sh"} {
		if !contains(got, keep) {
			t.Errorf("stripped output dropped a hand-added line %q:\n%s", keep, got)
		}
	}
	for _, gone := range []string{"/panel/job1", "/panel/job2", beginMarker, endMarker} {
		if contains(got, gone) {
			t.Errorf("stripped output still contains managed line %q:\n%s", gone, got)
		}
	}
	// A crontab with no managed block is returned unchanged.
	plain := "0 0 * * * /home/u/x.sh\n"
	if stripManagedBlock(plain) != plain {
		t.Error("stripManagedBlock changed a crontab with no managed block")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
