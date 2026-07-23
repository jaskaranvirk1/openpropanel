// Package cron materialises an account's scheduled jobs into its Linux user
// crontab. The panel owns a delimited block in the crontab (between BEGIN/END
// markers) and rewrites only that block on every change, so any lines a user
// added by hand are preserved.
//
// SECURITY: jobs run as the account's own non-root system user (the crontab
// owner), never root — the same trust boundary as the account's apps and git
// deploys. Validation keeps each job to exactly one crontab line: the five
// schedule fields are single tokens (no spaces/newlines that could shift columns
// or inject a line) and the command may not contain a newline.
package cron

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/system"
)

const (
	beginMarker = "# BEGIN Open ProPanel — managed cron jobs (do not edit by hand)"
	endMarker   = "# END Open ProPanel"
)

// Job is one schedule + command.
type Job struct {
	Minute, Hour, Dom, Month, Dow string
	Command                       string
}

// Manager writes account crontabs.
type Manager struct{ cfg *config.Config }

// New constructs a Manager.
func New(cfg *config.Config) *Manager { return &Manager{cfg: cfg} }

// nameRe matches month/weekday names (jan, mon, …). Case-insensitive letters.
var nameRe = regexp.MustCompile(`^[A-Za-z]{1,9}$`)

// ValidField reports whether a schedule field is a well-formed cron token that
// crond will accept: a comma list of items, each of which is "*", a value, a
// range "a-b", or any of those with a "/step". This is stricter than a character
// class so obviously-broken tokens (e.g. "*/0", "7-", "1,") are rejected up front
// with a friendly message rather than by crond at install time. It also forbids
// spaces/newlines, so a field can never shift columns or inject a crontab line.
func ValidField(f string) bool {
	if f == "" || len(f) > 120 {
		return false
	}
	for _, item := range strings.Split(f, ",") {
		if !validCronItem(item) {
			return false
		}
	}
	return true
}

func validCronItem(s string) bool {
	if s == "" {
		return false
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n < 1 {
			return false // step must be a positive integer (no "*/0")
		}
		s = s[:i]
	}
	if s == "*" {
		return true
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		return cronValue(s[:i]) && cronValue(s[i+1:]) // both ends required ("7-" invalid)
	}
	return cronValue(s)
}

// cronValue is a single numeric point (digits only — no sign) or a month/weekday
// name.
func cronValue(s string) bool {
	if s == "" {
		return false
	}
	digits := true
	for _, r := range s {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	return digits || nameRe.MatchString(s)
}

// CleanCommand trims and rejects a command that can't live on one crontab line.
// Everything else is kept verbatim (it runs as the tenant).
func CleanCommand(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("command is required")
	}
	if strings.ContainsAny(s, "\n\r\x00") {
		return "", errors.New("command must be a single line")
	}
	if len(s) > 4096 {
		return "", errors.New("command is too long")
	}
	return s, nil
}

// Line renders a job as a crontab line.
func (j Job) Line() string {
	return j.Minute + " " + j.Hour + " " + j.Dom + " " + j.Month + " " + j.Dow + " " + j.Command
}

// Sync rewrites the panel-managed block of systemUser's crontab to exactly jobs,
// preserving any hand-added lines outside the block. An empty jobs list clears
// the block. No-op on the dev host (no crontab).
func (m *Manager) Sync(ctx context.Context, systemUser string, jobs []Job) error {
	if systemUser == "" || systemUser == "root" {
		return errors.New("a non-root system user is required to schedule cron jobs")
	}
	if m.cfg.Dev {
		return nil
	}
	// A user with no crontab yet makes `crontab -l` exit non-zero AND emit
	// "no crontab for <user>" on stderr — which system.Run folds into the output.
	// Treat any error as an empty crontab so that noise is never written back.
	cur, err := system.Run(ctx, "crontab", "-u", systemUser, "-l")
	if err != nil {
		cur = ""
	}
	kept := stripManagedBlock(cur)

	var b strings.Builder
	kept = strings.TrimRight(kept, "\n")
	if kept != "" {
		b.WriteString(kept)
		b.WriteString("\n")
	}
	if len(jobs) > 0 {
		b.WriteString(beginMarker)
		b.WriteString("\n")
		for _, j := range jobs {
			b.WriteString(j.Line())
			b.WriteString("\n")
		}
		b.WriteString(endMarker)
		b.WriteString("\n")
	}
	// Writing an empty crontab is fine; crontab replaces the whole table.
	_, err = system.RunInput(ctx, b.String(), "crontab", "-u", systemUser, "-")
	return err
}

// stripManagedBlock returns crontab text with our BEGIN..END block removed.
func stripManagedBlock(crontab string) string {
	if !strings.Contains(crontab, beginMarker) {
		return crontab
	}
	var out []string
	skip := false
	for _, line := range strings.Split(crontab, "\n") {
		if strings.HasPrefix(line, beginMarker) {
			skip = true
			continue
		}
		if skip {
			if strings.HasPrefix(line, endMarker) {
				skip = false
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
