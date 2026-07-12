package filemanager

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

// Archive/extract limits — a hostile zip must not be able to fill the disk
// (zip bomb) or exhaust inodes. Uploads are already capped at the HTTP layer;
// these bound what an archive may EXPAND to.
const (
	maxUnzipBytes   = 512 << 20 // total uncompressed bytes per extraction
	maxUnzipEntries = 10000
)

// ErrArchiveTooBig means an archive would expand past the extraction limits.
var ErrArchiveTooBig = errors.New("archive is too large to extract")

// CopyEntry recursively copies srcRel to destRel inside the jail. Regular
// files and directories only — symlinks are skipped (copying a tenant-planted
// symlink would just duplicate a potential escape vector), and file
// permissions are preserved.
func (f *FS) CopyEntry(srcRel, destRel string) error {
	src, dest := norm(srcRel), norm(destRel)
	if src == "." || dest == "." {
		return ErrOutsideJail
	}
	// Refuse copying a directory into itself (infinite recursion).
	if dest == src || strings.HasPrefix(dest+"/", src+"/") {
		return errors.New("cannot copy a folder into itself")
	}
	fi, err := f.root.Stat(src)
	if err != nil {
		return mapErr(err)
	}
	return f.copyRec(src, dest, fi)
}

func (f *FS) copyRec(src, dest string, fi os.FileInfo) error {
	switch {
	case fi.Mode().IsDir():
		if err := f.root.Mkdir(dest, fi.Mode().Perm()); err != nil && !os.IsExist(err) {
			return mapErr(err)
		}
		d, err := f.root.Open(src)
		if err != nil {
			return mapErr(err)
		}
		des, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return err
		}
		for _, de := range des {
			cfi, err := de.Info()
			if err != nil {
				continue
			}
			if err := f.copyRec(path.Join(src, de.Name()), path.Join(dest, de.Name()), cfi); err != nil {
				return err
			}
		}
		return nil
	case fi.Mode().IsRegular():
		in, err := f.root.Open(src)
		if err != nil {
			return mapErr(err)
		}
		defer in.Close()
		out, err := f.root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
		if err != nil {
			return mapErr(err)
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	default:
		return nil // symlinks / devices: skipped deliberately
	}
}

// Zip archives the named entries of dirRel (recursively) into a zip written at
// destRel. Entry paths inside the archive are relative to dirRel. Symlinks are
// skipped.
func (f *FS) Zip(dirRel string, names []string, destRel string) error {
	dest := norm(destRel)
	if dest == "." {
		return ErrOutsideJail
	}
	out, err := f.root.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return mapErr(err)
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	dir := norm(dirRel)
	for _, name := range names {
		src := path.Join(dir, name)
		fi, err := f.root.Stat(src)
		if err != nil {
			return mapErr(err)
		}
		if err := f.zipRec(zw, src, name, fi, dest); err != nil {
			return err
		}
	}
	return zw.Close()
}

func (f *FS) zipRec(zw *zip.Writer, src, arcName string, fi os.FileInfo, skip string) error {
	if src == skip {
		return nil // never zip the archive into itself
	}
	switch {
	case fi.Mode().IsDir():
		if _, err := zw.Create(arcName + "/"); err != nil {
			return err
		}
		d, err := f.root.Open(src)
		if err != nil {
			return mapErr(err)
		}
		des, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return err
		}
		for _, de := range des {
			cfi, err := de.Info()
			if err != nil {
				continue
			}
			if err := f.zipRec(zw, path.Join(src, de.Name()), path.Join(arcName, de.Name()), cfi, skip); err != nil {
				return err
			}
		}
		return nil
	case fi.Mode().IsRegular():
		hdr := &zip.FileHeader{Name: arcName, Method: zip.Deflate, Modified: fi.ModTime()}
		hdr.SetMode(fi.Mode().Perm())
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		in, err := f.root.Open(src)
		if err != nil {
			return mapErr(err)
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	default:
		return nil // symlinks: skipped
	}
}

// Unzip extracts the zip at srcRel into destDirRel, returning the rel paths it
// created (for post-extract chown). Entry names are re-jailed (zip-slip),
// symlink entries are skipped, and expansion is bounded by maxUnzipBytes /
// maxUnzipEntries so a zip bomb cannot fill the disk.
func (f *FS) Unzip(srcRel, destDirRel string) ([]string, error) {
	return f.unzipTo(srcRel, destDirRel, maxUnzipBytes, maxUnzipEntries)
}

// unzipTo is Unzip with explicit limits (so the byte/entry caps are testable
// without writing gigabytes).
func (f *FS) unzipTo(srcRel, destDirRel string, maxBytes int64, maxEntries int) ([]string, error) {
	src := norm(srcRel)
	fh, err := f.root.Open(src)
	if err != nil {
		return nil, mapErr(err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(fh, fi.Size())
	if err != nil {
		return nil, errors.New("not a valid zip archive")
	}
	if len(zr.File) > maxEntries {
		return nil, ErrArchiveTooBig
	}

	destDir := norm(destDirRel)
	var created []string
	var total int64 // bytes ACTUALLY written, never the attacker-declared size
	for _, zf := range zr.File {
		// Zip-slip guard: normalise the entry name and refuse anything that
		// cleans to an escape. os.Root re-enforces this at the syscall level.
		name := norm(strings.ReplaceAll(zf.Name, `\`, "/"))
		if name == "." || strings.HasPrefix(name, "../") {
			continue
		}
		target := path.Join(destDir, name)
		mode := zf.Mode()
		if mode&os.ModeSymlink != 0 {
			continue // never materialise archive-supplied symlinks
		}
		if zf.FileInfo().IsDir() {
			if err := f.mkdirAll(target); err != nil {
				return created, err
			}
			created = append(created, target)
			continue
		}
		if err := f.mkdirAll(path.Dir(target)); err != nil {
			return created, err
		}
		perm := mode.Perm()
		if perm == 0 {
			perm = 0o644
		}
		out, err := f.root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
		if err != nil {
			return created, mapErr(err)
		}
		in, err := zf.Open()
		if err != nil {
			out.Close()
			return created, err
		}
		// Bound this entry by the REMAINING global budget and account for what
		// was ACTUALLY written — never trust zf.UncompressedSize64, which the
		// archive author controls (declaring 0 would otherwise let each entry
		// stream the full budget). +1 so an entry that exactly consumes the
		// remainder is still detected as overflowing.
		n, cerr := io.Copy(out, io.LimitReader(in, maxBytes-total+1))
		in.Close()
		out.Close()
		if cerr != nil {
			return created, cerr
		}
		total += n
		created = append(created, target)
		if total > maxBytes {
			return created, ErrArchiveTooBig
		}
	}
	return created, nil
}

// ChownTree recursively hands rel (and everything under it) to uid/gid.
func (f *FS) ChownTree(rel string, uid, gid int) error {
	rel = norm(rel)
	fi, err := f.root.Stat(rel)
	if err != nil {
		return mapErr(err)
	}
	if err := f.root.Chown(rel, uid, gid); err != nil {
		return mapErr(err)
	}
	if !fi.IsDir() {
		return nil
	}
	d, err := f.root.Open(rel)
	if err != nil {
		return mapErr(err)
	}
	des, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, de := range des {
		_ = f.ChownTree(path.Join(rel, de.Name()), uid, gid) // best-effort per child
	}
	return nil
}

// mkdirAll creates rel and its parents inside the jail (0755).
func (f *FS) mkdirAll(rel string) error {
	rel = norm(rel)
	if rel == "." {
		return nil
	}
	parts := strings.Split(rel, "/")
	acc := ""
	for _, p := range parts {
		acc = path.Join(acc, p)
		if err := f.root.Mkdir(acc, 0o755); err != nil && !os.IsExist(err) {
			return mapErr(err)
		}
	}
	return nil
}
