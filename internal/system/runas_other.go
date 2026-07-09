//go:build !linux

package system

import (
	"context"
	"errors"
)

// RunAs is only supported on Linux. On the dev host the deploy layer short-
// circuits before calling this (like other system-mutating actions).
func RunAs(ctx context.Context, uid, gid uint32, env []string, name string, args ...string) (string, error) {
	return "", errors.New("running a command as another user is only supported on Linux")
}
