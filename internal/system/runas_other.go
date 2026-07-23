//go:build !linux

package system

import (
	"context"
	"errors"
	"io"
)

// RunAs is only supported on Linux. On the dev host the deploy layer short-
// circuits before calling this (like other system-mutating actions).
func RunAs(ctx context.Context, uid, gid uint32, dir string, env []string, name string, args ...string) (string, error) {
	return "", errors.New("running a command as another user is only supported on Linux")
}

// RunAsOut is only supported on Linux (see RunAs).
func RunAsOut(ctx context.Context, uid, gid uint32, dir string, env []string, out io.Writer, name string, args ...string) error {
	return errors.New("running a command as another user is only supported on Linux")
}
