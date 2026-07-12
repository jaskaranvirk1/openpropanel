//go:build !linux

package filemanager

import "os"

// fileOwner has no portable meaning off Linux (the dev host), so ownership is
// reported as unknown. Chown is a no-op in dev mode anyway.
func fileOwner(fi os.FileInfo) (uid, gid int, owner, group string) {
	return -1, -1, "", ""
}
