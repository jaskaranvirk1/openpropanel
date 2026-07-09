//go:build linux

package system

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// RunAs runs a command as the given uid/gid (dropping supplementary groups),
// with an optional custom environment. The panel runs as root and uses this to
// execute git as the tenant's own system user — NEVER as root — so a
// tenant-owned repo cannot use git hooks / core.sshCommand to execute as root.
func RunAs(ctx context.Context, uid, gid uint32, env []string, name string, args ...string) (string, error) {
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	Audit("run-as", fmt.Sprintf("uid=%d %s %s", uid, name, strings.Join(args, " ")))
	cmd := exec.CommandContext(ctx, name, args...)
	// Groups left nil => setgroups([]) is called, dropping root's supplementary
	// groups so the child truly runs with only the tenant's identity.
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
