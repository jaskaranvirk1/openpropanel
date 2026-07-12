//go:build linux

package filemanager

import (
	"os"
	osuser "os/user"
	"strconv"
	"sync"
	"syscall"
)

// uid/gid → name caches: a directory listing resolves the same handful of
// owners repeatedly, and passwd/group lookups are not free.
var (
	nameMu     sync.Mutex
	userCache  = map[int]string{}
	groupCache = map[int]string{}
)

// fileOwner extracts the numeric uid/gid and resolved names from a FileInfo.
// Returns empty names on a platform/filesystem that does not expose them.
func fileOwner(fi os.FileInfo) (uid, gid int, owner, group string) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, "", ""
	}
	uid, gid = int(st.Uid), int(st.Gid)
	return uid, gid, lookupUID(uid), lookupGID(gid)
}

func lookupUID(uid int) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	if n, ok := userCache[uid]; ok {
		return n
	}
	n := strconv.Itoa(uid)
	if u, err := osuser.LookupId(n); err == nil {
		n = u.Username
	}
	userCache[uid] = n
	return n
}

func lookupGID(gid int) string {
	nameMu.Lock()
	defer nameMu.Unlock()
	if n, ok := groupCache[gid]; ok {
		return n
	}
	n := strconv.Itoa(gid)
	if g, err := osuser.LookupGroupId(n); err == nil {
		n = g.Name
	}
	groupCache[gid] = n
	return n
}
