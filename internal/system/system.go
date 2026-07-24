// Package system is the single, audited choke-point for everything Open ProPanel
// does to the host: running external commands, reading live resource usage, and
// controlling systemd services. Centralising command execution here keeps the
// privileged surface small and easy to review.
package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// DefaultTimeout bounds any command that does not carry its own deadline.
const DefaultTimeout = 60 * time.Second

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

// maxAuditBytes bounds the audit log; it rotates once (path -> path.1) at this
// size so a busy or hostile workload cannot fill the disk.
const maxAuditBytes = 16 << 20

var (
	auditMu   sync.Mutex
	auditW    *os.File // nil until EnableAudit; guarded by auditMu
	auditPath string
	auditSize int64
)

// EnableAudit opens (append-only, 0600) an audit log at path and directs every
// privileged action through it. Best-effort: callers log the error but continue.
// Secrets are never written — RunInput's stdin (SQL, passwords) is not logged,
// and callers pass only non-sensitive descriptors to Audit.
func EnableAudit(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	auditMu.Lock()
	auditW, auditPath = f, path
	if fi, e := f.Stat(); e == nil {
		auditSize = fi.Size()
	}
	auditMu.Unlock()
	return nil
}

// Audit appends one timestamped line to the audit log (no-op until enabled).
// detail must not contain secrets. Control characters in kind/detail are
// stripped so an attacker-influenced value (e.g. a domain or operator-set ACME
// email) can never split or forge audit lines.
func Audit(kind, detail string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditW == nil {
		return
	}
	line := fmt.Sprintf("%s %s %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		sanitizeAudit(kind), sanitizeAudit(detail))
	if auditSize+int64(len(line)) > maxAuditBytes {
		rotateAuditLocked()
	}
	if n, err := auditW.WriteString(line); err == nil {
		auditSize += int64(n)
	}
}

// rotateAuditLocked rotates the log once (path -> path.1). Caller holds auditMu.
func rotateAuditLocked() {
	if auditW == nil || auditPath == "" {
		return
	}
	_ = auditW.Close()
	_ = os.Rename(auditPath, auditPath+".1") // best-effort; replaces any prior .1
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		auditW = nil
		return
	}
	auditW, auditSize = f, 0
}

func sanitizeAudit(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// Run executes a command and returns its combined stdout+stderr. If the context
// has no deadline, DefaultTimeout is applied. The returned error embeds the
// output so callers (and logs) get actionable diagnostics.
//
// Arguments are passed as a slice — never through a shell — so there is no shell
// interpolation and therefore no shell-injection surface.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	// Audit every mutating command. Read-only status polls (systemctl
	// is-active/is-enabled, run every few seconds by the dashboard) are skipped
	// so the log stays a record of actions, not noise.
	if !(name == "systemctl" && len(args) > 0 && (args[0] == "is-active" || args[0] == "is-enabled")) {
		Audit("run", name+" "+strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// RunHost runs a command OUTSIDE Open ProPanel's own service sandbox by asking
// systemd (PID 1) to execute it in a fresh transient unit (systemd-run). The
// panel's unit sets ProtectSystem=true, which mounts /usr read-only and so blocks
// operations that must write there — notably a package install. A transient unit
// is not subject to the panel's sandbox, so those operations succeed. Like Run,
// arguments are passed as a slice — never through a shell — so there is no
// shell-injection surface; callers must still pass only trusted, fixed arguments.
func RunHost(ctx context.Context, name string, args ...string) (string, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	Audit("run-host", name+" "+strings.Join(args, " "))
	full := append([]string{"--pipe", "--wait", "--collect", "--quiet", "--", name}, args...)
	cmd := exec.CommandContext(ctx, "systemd-run", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemd-run %s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// RunInput is like Run but feeds stdin to the command. It is used to pipe SQL
// to the mysql client so that secrets (passwords) never appear in the process
// argument list. Like Run, arguments are passed as a slice — no shell.
func RunInput(ctx context.Context, stdin, name string, args ...string) (string, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ---------------------------------------------------------------------------
// systemd service control
// ---------------------------------------------------------------------------

// ServiceAction runs `systemctl <action> <unit>` (start|stop|restart|reload|
// enable|disable).
func ServiceAction(ctx context.Context, action, unit string) error {
	_, err := Run(ctx, "systemctl", action, unit)
	return err
}

// ServiceActive reports whether a unit is currently active (running).
func ServiceActive(ctx context.Context, unit string) bool {
	out, _ := Run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

// ServiceEnabled reports whether a unit is enabled at boot.
func ServiceEnabled(ctx context.Context, unit string) bool {
	out, _ := Run(ctx, "systemctl", "is-enabled", unit)
	return strings.TrimSpace(out) == "enabled"
}

// DaemonReload reloads systemd's unit definitions after a unit file changes.
func DaemonReload(ctx context.Context) error {
	_, err := Run(ctx, "systemctl", "daemon-reload")
	return err
}

// JournalTail returns the last n journald lines for a unit.
func JournalTail(ctx context.Context, unit string, n int) (string, error) {
	return Run(ctx, "journalctl", "-u", unit, "-n", fmt.Sprint(n), "--no-pager")
}

// ServiceInfo is a snapshot of a managed service for the dashboard.
type ServiceInfo struct {
	Unit    string
	Active  bool
	Enabled bool
}

// InspectServices returns status for a set of units.
func InspectServices(ctx context.Context, units ...string) []ServiceInfo {
	out := make([]ServiceInfo, 0, len(units))
	for _, u := range units {
		out = append(out, ServiceInfo{
			Unit:    u,
			Active:  ServiceActive(ctx, u),
			Enabled: ServiceEnabled(ctx, u),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Live resource statistics
// ---------------------------------------------------------------------------

// Stats is a point-in-time snapshot of host resource usage. Each field degrades
// gracefully to zero/empty if the underlying metric is unavailable (e.g. when
// developing on a non-Linux host).
type Stats struct {
	Hostname        string
	OS              string
	Uptime          time.Duration
	CPUPercent      float64
	CPUCores        int
	MemUsedPercent  float64
	MemUsed         uint64
	MemTotal        uint64
	DiskUsedPercent float64
	DiskUsed        uint64
	DiskTotal       uint64
	Load1           float64
	Load5           float64
	Load15          float64
}

// Collect samples current host statistics. It briefly blocks (~250ms) to
// measure CPU utilisation.
func Collect() Stats {
	var s Stats

	if info, err := host.Info(); err == nil {
		s.Hostname = info.Hostname
		s.OS = fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion)
		s.Uptime = time.Duration(info.Uptime) * time.Second
	}
	s.CPUCores = runtime.NumCPU()

	if pct, err := cpu.Percent(250*time.Millisecond, false); err == nil && len(pct) > 0 {
		s.CPUPercent = pct[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		s.MemUsedPercent = vm.UsedPercent
		s.MemUsed = vm.Used
		s.MemTotal = vm.Total
	}
	if du, err := disk.Usage(rootPath()); err == nil {
		s.DiskUsedPercent = du.UsedPercent
		s.DiskUsed = du.Used
		s.DiskTotal = du.Total
	}
	if avg, err := load.Avg(); err == nil {
		s.Load1, s.Load5, s.Load15 = avg.Load1, avg.Load5, avg.Load15
	}
	return s
}

func rootPath() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}
