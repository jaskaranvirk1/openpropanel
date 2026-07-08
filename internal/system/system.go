// Package system is the single, audited choke-point for everything Open ProPanel
// does to the host: running external commands, reading live resource usage, and
// controlling systemd services. Centralising command execution here keeps the
// privileged surface small and easy to review.
package system

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// DefaultTimeout bounds any command that does not carry its own deadline.
const DefaultTimeout = 60 * time.Second

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
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
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
