package filemanager

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func newFS(t *testing.T) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	fs, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs, root
}

func mustWrite(t *testing.T, fs *FS, rel, content string) {
	t.Helper()
	if err := fs.WriteText(rel, content); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestCopyEntryFileAndDir(t *testing.T) {
	fs, _ := newFS(t)
	mustWrite(t, fs, "a.txt", "hello")
	if err := fs.CopyEntry("a.txt", "b.txt"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fs.ReadText("b.txt"); got != "hello" {
		t.Errorf("copied content = %q", got)
	}
	// Recursive dir copy.
	if err := fs.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, fs, "dir/inner.txt", "x")
	if err := fs.CopyEntry("dir", "dir2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fs.ReadText("dir2/inner.txt"); got != "x" {
		t.Error("recursive copy lost the inner file")
	}
	// A folder must never be copied into itself.
	if err := fs.CopyEntry("dir", "dir/sub"); err == nil {
		t.Error("copy into itself should be refused")
	}
	// Copy must not overwrite an existing target.
	if err := fs.CopyEntry("a.txt", "b.txt"); err == nil {
		t.Error("copy over an existing file should fail (O_EXCL)")
	}
}

func TestZipUnzipRoundtrip(t *testing.T) {
	fs, _ := newFS(t)
	mustWrite(t, fs, "one.txt", "1")
	_ = fs.Mkdir("sub")
	mustWrite(t, fs, "sub/two.txt", "2")

	if err := fs.Zip("", []string{"one.txt", "sub"}, "out.zip"); err != nil {
		t.Fatalf("zip: %v", err)
	}
	_ = fs.Mkdir("extracted")
	created, err := fs.Unzip("out.zip", "extracted")
	if err != nil {
		t.Fatalf("unzip: %v", err)
	}
	if len(created) == 0 {
		t.Fatal("unzip reported nothing created")
	}
	if got, _ := fs.ReadText("extracted/one.txt"); got != "1" {
		t.Errorf("extracted one.txt = %q", got)
	}
	if got, _ := fs.ReadText("extracted/sub/two.txt"); got != "2" {
		t.Errorf("extracted sub/two.txt = %q", got)
	}
}

// The archive must not include itself (zipping "." with the archive landing in
// the same dir would otherwise recurse).
func TestZipExcludesItself(t *testing.T) {
	fs, _ := newFS(t)
	_ = fs.Mkdir("d")
	mustWrite(t, fs, "d/f.txt", "x")
	if err := fs.Zip("", []string{"d"}, "d/self.zip"); err != nil {
		// Also acceptable: an error. But if it succeeds, it must not contain itself.
		return
	}
	created, err := fs.Unzip("d/self.zip", "out")
	if err != nil {
		t.Fatalf("unzip: %v", err)
	}
	for _, c := range created {
		if filepath.Base(c) == "self.zip" {
			t.Error("archive zipped itself")
		}
	}
}

// A hostile zip with ../ entries must never write outside the destination.
func TestUnzipZipSlipContained(t *testing.T) {
	fs, root := newFS(t)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../../evil.txt")
	_, _ = w.Write([]byte("pwned"))
	w2, _ := zw.Create("ok.txt")
	_, _ = w2.Write([]byte("fine"))
	_ = zw.Close()
	if err := fs.WriteText("evil.zip", buf.String()); err != nil {
		t.Fatal(err)
	}

	_ = fs.Mkdir("dest")
	if _, err := fs.Unzip("evil.zip", "dest"); err != nil {
		t.Fatalf("unzip: %v", err)
	}
	// The traversal entry must be skipped; the benign one extracted.
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "evil.txt")); err == nil {
		t.Fatal("zip-slip escaped the jail — evil.txt written outside root")
	}
	if _, err := os.Stat(filepath.Join(root, "evil.txt")); err == nil {
		t.Error("traversal entry should be skipped entirely, not flattened into the root")
	}
	if got, _ := fs.ReadText("dest/ok.txt"); got != "fine" {
		t.Error("benign entry should still extract")
	}
}

// An archive above the entry cap must be refused.
func TestUnzipEntryCapRefused(t *testing.T) {
	fs, _ := newFS(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < maxUnzipEntries+1; i++ {
		_, _ = zw.CreateHeader(&zip.FileHeader{Name: "f" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "/x.txt"})
	}
	_ = zw.Close()
	if err := fs.WriteText("bomb.zip", buf.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Unzip("bomb.zip", ""); err == nil {
		t.Error("an archive above the entry cap must be refused")
	}
}

// The BYTE cap must bound bytes actually written, not the archive's declared
// sizes — a zip bomb that under-declares its entry sizes must still be stopped
// after roughly the budget, not after the full budget PER entry.
func TestUnzipByteCapBoundsActualBytes(t *testing.T) {
	fs, _ := newFS(t)
	// Ten entries of 5 KiB each = 50 KiB of real payload; extract with a tiny
	// 8 KiB budget. Honestly-built entries: the point is that the cap counts
	// what is WRITTEN, so extraction must abort well before all 50 KiB land.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	payload := bytes.Repeat([]byte("A"), 5<<10)
	for i := 0; i < 10; i++ {
		w, _ := zw.Create("e" + string(rune('0'+i)) + ".txt")
		_, _ = w.Write(payload)
	}
	_ = zw.Close()
	if err := fs.WriteText("many.zip", buf.String()); err != nil {
		t.Fatal(err)
	}
	_ = fs.Mkdir("d")
	created, err := fs.unzipTo("many.zip", "d", 8<<10, 1000)
	if err != ErrArchiveTooBig {
		t.Fatalf("expected ErrArchiveTooBig once the byte budget is exceeded, got %v", err)
	}
	// The bytes actually written must be bounded by roughly the budget — never
	// the full 50 KiB. Sum the sizes of what landed.
	var written int64
	for _, rel := range created {
		if fi, e := fs.root.Stat(norm(rel)); e == nil {
			written += fi.Size()
		}
	}
	if written > (8<<10)+(5<<10) { // budget + at most one in-flight entry
		t.Errorf("byte cap did not bound actual writes: %d bytes landed", written)
	}
}

// A hand-crafted zip that LIES about its uncompressed size (declares 0 in the
// header while carrying a real stored payload) must not be able to write past
// the budget — the cap must never trust the declared size.
func TestUnzipByteCapIgnoresDeclaredSize(t *testing.T) {
	fs, _ := newFS(t)
	payload := bytes.Repeat([]byte("B"), 4<<10) // 4 KiB stored, header says 0
	crc := crc32.ChecksumIEEE(payload)
	var b bytes.Buffer
	name := "big.txt"
	// Local file header with STORE method and all-zero CRC/size fields.
	writeU32(&b, 0x04034b50) // local file header signature
	writeU16(&b, 20)         // version needed
	writeU16(&b, 0)          // flags
	writeU16(&b, 0)          // method: store
	writeU16(&b, 0)          // mod time
	writeU16(&b, 0)          // mod date
	writeU32(&b, 0)          // CRC-32 (lie: 0)
	writeU32(&b, 0)          // compressed size (lie: 0)
	writeU32(&b, 0)          // uncompressed size (lie: 0)
	writeU16(&b, uint16(len(name)))
	writeU16(&b, 0)
	b.WriteString(name)
	dataOffset := b.Len()
	b.Write(payload)
	// Central directory pointing at the lying local header.
	cdOffset := b.Len()
	writeU32(&b, 0x02014b50) // central dir signature
	writeU16(&b, 20)         // version made by
	writeU16(&b, 20)         // version needed
	writeU16(&b, 0)          // flags
	writeU16(&b, 0)          // method: store
	writeU16(&b, 0)
	writeU16(&b, 0)
	writeU32(&b, crc) // real CRC here so the reader can open the entry
	writeU32(&b, 0)   // compressed size (lie: 0)
	writeU32(&b, 0)   // uncompressed size (lie: 0)
	writeU16(&b, uint16(len(name)))
	writeU16(&b, 0)
	writeU16(&b, 0)
	writeU16(&b, 0)
	writeU16(&b, 0)
	writeU32(&b, 0)
	writeU32(&b, uint32(0)) // local header offset
	b.WriteString(name)
	// End of central directory.
	writeU32(&b, 0x06054b50)
	writeU16(&b, 0)
	writeU16(&b, 0)
	writeU16(&b, 1)
	writeU16(&b, 1)
	writeU32(&b, uint32(b.Len()-cdOffset))
	writeU32(&b, uint32(cdOffset))
	writeU16(&b, 0)
	_ = dataOffset

	if err := fs.WriteText("lie.zip", b.String()); err != nil {
		t.Fatal(err)
	}
	_ = fs.Mkdir("out")
	// Budget of 1 KiB; the entry really holds 4 KiB. Whatever the stdlib does
	// with the lie, OUR accounting must cap writes near the budget.
	created, _ := fs.unzipTo("lie.zip", "out", 1<<10, 1000)
	var written int64
	for _, rel := range created {
		if fi, e := fs.root.Stat(norm(rel)); e == nil {
			written += fi.Size()
		}
	}
	if written > 2<<10 {
		t.Errorf("declared-size lie let %d bytes through a 1 KiB budget", written)
	}
}

func writeU16(b *bytes.Buffer, v uint16) { b.Write([]byte{byte(v), byte(v >> 8)}) }
func writeU32(b *bytes.Buffer, v uint32) {
	b.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}
