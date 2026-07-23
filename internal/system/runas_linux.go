//go:build linux

package system

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
)

// RunAs runs a command as the given uid/gid (dropping supplementary groups), in
// working directory dir (when non-empty), with an optional custom environment.
// The panel runs as root and uses this to execute git AND tenant build commands
// as the tenant's own system user — NEVER as root — so a tenant-owned repo
// cannot use git hooks / core.sshCommand / a build script to execute as root.
func RunAs(ctx context.Context, uid, gid uint32, dir string, env []string, name string, args ...string) (string, error) {
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	Audit("run-as", fmt.Sprintf("uid=%d %s %s", uid, name, strings.Join(args, " ")))
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
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

// RunAsOut is like RunAs but STREAMS the child's combined stdout+stderr into out
// (an io.Writer the caller bounds), instead of buffering it all in memory. It is
// used for tenant build commands, whose output length the tenant controls — a
// caller-supplied capped writer keeps a runaway build from OOMing the root panel.
func RunAsOut(ctx context.Context, uid, gid uint32, dir string, env []string, out io.Writer, name string, args ...string) error {
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}
	Audit("run-as", fmt.Sprintf("uid=%d %s %s", uid, name, strings.Join(args, " ")))
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}
