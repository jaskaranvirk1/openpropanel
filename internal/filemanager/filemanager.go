// Package filemanager provides safe, jailed filesystem operations for the web
// file manager. Confinement is delegated to os.Root (Go 1.24+): every path is
// resolved *within* the root using openat-style syscalls that refuse to follow
// symlinks or ".." out of the root, atomically. Because the panel runs as root
// and a hosting user can write symlinks into their own docroot (via SSH/SFTP/
// PHP), this kernel-enforced confinement — not path-string checks — is what
// prevents the panel from reading or writing outside the jail.
package filemanager

import (
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxEditBytes caps the size of a file that may be loaded into the editor.
const MaxEditBytes = 1 << 20 // 1 MiB

var (
	// ErrOutsideJail means a path escaped (or tried to escape) the jail root.
	ErrOutsideJail = errors.New("path is outside the allowed directory")
	// ErrTooLarge means a file is too big to edit in the browser.
	ErrTooLarge = errors.New("file is too large to edit")
	// ErrBinary means a file does not look like editable text.
	ErrBinary = errors.New("file is not editable text")
	// ErrIsDir means a directory was given where a file was expected.
	ErrIsDir = errors.New("path is a directory")
)

// Entry describes one directory item for the listing UI.
type Entry struct {
	Name    string
	IsDir   bool
	IsLink  bool // symbolic link (its target is never followed for listing)
	Size    int64
	Perm    string // octal, e.g. "0644"
	Sym     string // symbolic perms, e.g. "rw-r--r--"
	Mode    string // one-letter type: "d" dir, "l" link, "-" file
	UID     int
	GID     int
	Owner   string // resolved user name (or numeric uid as a string)
	Group   string // resolved group name (or numeric gid as a string)
	ModTime time.Time
}

// fillMeta populates the ownership/permission fields of e from fi.
func fillMeta(e *Entry, fi os.FileInfo) {
	m := fi.Mode()
	e.Perm = "0" + strconv.FormatUint(uint64(m.Perm()), 8)
	e.Sym = permString(m)
	e.IsLink = m&os.ModeSymlink != 0
	switch {
	case e.IsLink:
		e.Mode = "l"
	case m.IsDir():
		e.Mode = "d"
	default:
		e.Mode = "-"
	}
	e.UID, e.GID, e.Owner, e.Group = fileOwner(fi)
}

// permString renders the 9-bit rwx form of a mode, e.g. "rwxr-x---".
func permString(m os.FileMode) string {
	const set = "rwxrwxrwx"
	b := []byte("---------")
	p := m.Perm()
	for i := 0; i < 9; i++ {
		if p&(1<<uint(8-i)) != 0 {
			b[i] = set[i]
		}
	}
	return string(b)
}

// FS is a filesystem confined to a root directory.
type FS struct {
	root *os.Root
}

// New opens a jailed view of root (which must be an existing directory).
func New(root string) (*FS, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &FS{root: r}, nil
}

// Close releases the underlying root handle.
func (f *FS) Close() error { return f.root.Close() }

// norm turns a user path into a clean root-relative name with no leading slash
// or "..". os.Root still enforces the real confinement; this just tidies input.
func norm(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "."
	}
	return p
}

// mapErr normalises an os.Root escape rejection to ErrOutsideJail.
func mapErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "escapes from parent") {
		return ErrOutsideJail
	}
	return err
}

// List returns the entries in the directory at rel (sorted dirs-first).
func (f *FS) List(rel string) ([]Entry, error) {
	d, err := f.root.Open(norm(rel))
	if err != nil {
		return nil, mapErr(err)
	}
	defer d.Close()
	des, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		e := Entry{
			Name:    de.Name(),
			IsDir:   de.IsDir(),
			Size:    fi.Size(),
			ModTime: fi.ModTime(),
		}
		fillMeta(&e, fi)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// StatEntry returns metadata for a single path (for the properties/permissions
// dialog). The entry itself is lstat'd via the directory listing semantics —
// a symlink is reported as a link, not its target.
func (f *FS) StatEntry(rel string) (Entry, error) {
	n := norm(rel)
	fi, err := f.root.Stat(n)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	e := Entry{Name: path.Base(n), IsDir: fi.IsDir(), Size: fi.Size(), ModTime: fi.ModTime()}
	if e.Name == "." {
		e.Name = ""
	}
	fillMeta(&e, fi)
	return e, nil
}

// IsDir reports whether rel is a directory.
func (f *FS) IsDir(rel string) bool {
	fi, err := f.root.Stat(norm(rel))
	return err == nil && fi.IsDir()
}

// ReadText loads a text file for editing, rejecting oversized or binary files.
func (f *FS) ReadText(rel string) (string, error) {
	fh, err := f.root.Open(norm(rel))
	if err != nil {
		return "", mapErr(err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", ErrIsDir
	}
	if fi.Size() > MaxEditBytes {
		return "", ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(fh, MaxEditBytes+1))
	if err != nil {
		return "", err
	}
	if !looksTextual(b) {
		return "", ErrBinary
	}
	return string(b), nil
}

// WriteText writes content to rel (0644), creating or truncating it. os.Root's
// OpenFile refuses to follow a symlink at the final component, so it can never
// write through an attacker-planted symlink.
func (f *FS) WriteText(rel, content string) error {
	fh, err := f.root.OpenFile(norm(rel), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return mapErr(err)
	}
	defer fh.Close()
	_, err = fh.WriteString(content)
	return err
}

// CreateFile creates an empty file, failing if it already exists.
func (f *FS) CreateFile(rel string) error {
	fh, err := f.root.OpenFile(norm(rel), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return mapErr(err)
	}
	return fh.Close()
}

// Mkdir creates a directory (0755).
func (f *FS) Mkdir(rel string) error {
	return mapErr(f.root.Mkdir(norm(rel), 0o755))
}

// Delete removes a file or directory (recursively). The jail root itself cannot
// be removed.
func (f *FS) Delete(rel string) error {
	n := norm(rel)
	if n == "." {
		return ErrOutsideJail
	}
	return mapErr(f.root.RemoveAll(n))
}

// Rename moves within the jail.
func (f *FS) Rename(oldRel, newRel string) error {
	o, nw := norm(oldRel), norm(newRel)
	if o == "." || nw == "." {
		return ErrOutsideJail
	}
	return mapErr(f.root.Rename(o, nw))
}

// Chmod sets the rwx permissions from an octal string like "0644". The UI can
// only express the 9 rwx bits, so any existing setuid/setgid/sticky bits are
// PRESERVED — a plain chmod must never silently strip the setgid bit off a
// group-shared directory. (New special bits still cannot be set here: the
// input is capped at 0o777.)
func (f *FS) Chmod(rel, octal string) error {
	mode, err := strconv.ParseUint(strings.TrimSpace(octal), 8, 32)
	if err != nil || mode > 0o777 {
		return errors.New("invalid permissions")
	}
	n := norm(rel)
	special := os.FileMode(0)
	if fi, e := f.root.Stat(n); e == nil {
		special = fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	}
	return mapErr(f.root.Chmod(n, os.FileMode(mode)|special))
}

// Chown hands a path to a uid/gid (used to give panel-created files to the
// site's system user).
func (f *FS) Chown(rel string, uid, gid int) error {
	return mapErr(f.root.Chown(norm(rel), uid, gid))
}

// OpenRead opens a regular file for download. The caller must close it.
func (f *FS) OpenRead(rel string) (*os.File, os.FileInfo, error) {
	fh, err := f.root.Open(norm(rel))
	if err != nil {
		return nil, nil, mapErr(err)
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, nil, err
	}
	if fi.IsDir() {
		fh.Close()
		return nil, nil, ErrIsDir
	}
	return fh, fi, nil
}

// SaveUploadReader streams an upload into dirRel under a safe base name and
// returns the written file's rel path (for a post-write chown).
func (f *FS) SaveUploadReader(dirRel, filename string, src io.Reader) (string, error) {
	name := path.Base(strings.ReplaceAll(filename, `\`, "/"))
	if name == "" || name == "." || name == ".." {
		return "", errors.New("invalid file name")
	}
	rel := path.Join(norm(dirRel), name)
	fh, err := f.root.OpenFile(norm(rel), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", mapErr(err)
	}
	defer fh.Close()
	if _, err := io.Copy(fh, src); err != nil {
		return "", err
	}
	return rel, nil
}

// looksTextual reports whether b appears to be text (no NUL bytes in the sample).
func looksTextual(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
	}
	return true
}
