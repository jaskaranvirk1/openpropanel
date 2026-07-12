package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	osuser "os/user"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/filemanager"
	"github.com/openpropanel/openpropanel/internal/store"
)

const maxUploadBytes = 64 << 20 // 64 MiB

type crumb struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type fileRow struct {
	filemanager.Entry
	RelPath string
}

type filesVM struct {
	Site    *store.Site
	Path    string // current directory (rel)
	Parent  string // parent directory (rel), "" at root
	AtRoot  bool
	Crumbs  []crumb
	Entries []fileRow
	Sites   []*store.Site // populated for the chooser (when no Site is selected)
	IsAdmin bool
}

type fileEditVM struct {
	Site    *store.Site
	Path    string // file rel
	Dir     string // parent dir (return target)
	Name    string
	Content string
}

// openFS loads the site named by the "site" param, checks the caller may manage
// it, and returns a filesystem jailed to that site's document root.
func (s *Server) openFS(w http.ResponseWriter, r *http.Request) (*filemanager.FS, *store.Site, bool) {
	viewer := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.FormValue("site"), 10, 64)
	if err != nil {
		http.Error(w, "bad site id", http.StatusBadRequest)
		return nil, nil, false
	}
	site, err := s.store.SiteByID(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return nil, nil, false
	}
	if viewer.Role != store.RoleAdmin && site.UserID != viewer.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, nil, false
	}
	// Re-validate the doc root at open time (not just at creation): a non-admin
	// whose doc root lives in a tenant-writable location could have swapped it
	// for a symlink into another tenant's tree. SafeDocRoot resolves symlinks
	// and confirms it is still inside the owner's permitted area.
	root, err := s.domains.SafeDocRoot(site, viewer.Role == store.RoleAdmin)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, nil, false
	}
	fs, err := filemanager.New(root)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, false
	}
	return fs, site, true
}

func (s *Server) getFiles(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())

	// No site selected -> show the chooser (browse any of your projects' files).
	if r.FormValue("site") == "" {
		var sites []*store.Site
		var err error
		if viewer.Role == store.RoleAdmin {
			sites, err = s.store.ListSites()
		} else {
			sites, err = s.store.ListSitesByUser(viewer.ID)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.render.page(w, http.StatusOK, "files", pageData{
			User: viewer, Active: "files",
			Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
			Data:  filesVM{Sites: sites, IsAdmin: viewer.Role == store.RoleAdmin},
		})
		return
	}

	// In-site view: render the explorer SHELL. The rich listing (entries,
	// sort, ownership, context menus) is driven client-side by files.js, which
	// fetches GET /files/api/list — so navigating folders never reloads the page.
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	fs.Close()
	s.render.page(w, http.StatusOK, "files", pageData{
		User: viewer, Active: "files",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data:  filesVM{Site: site, Path: cleanRel(r.FormValue("path"))},
	})
}

// fileJSON is one directory entry as sent to the browser explorer.
type fileJSON struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Link  bool   `json:"link"`
	Size  int64  `json:"size"`
	Perm  string `json:"perm"` // octal, e.g. "0644"
	Sym   string `json:"sym"`  // symbolic, e.g. "rw-r--r--"
	Owner string `json:"owner"`
	Group string `json:"group"`
	MTime int64  `json:"mtime"` // unix seconds
}

// getFilesList returns a directory listing as JSON for the explorer UI.
func (s *Server) getFilesList(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	cur := cleanRel(r.FormValue("path"))
	if cur != "" && !fs.IsDir(cur) {
		cur = ""
	}
	entries, err := fs.List(cur)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": userError(err)})
		return
	}
	items := make([]fileJSON, 0, len(entries))
	dirs, files, hidden := 0, 0, 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name, ".") {
			hidden++
		}
		if e.IsDir {
			dirs++
		} else {
			files++
		}
		items = append(items, fileJSON{
			Name: e.Name, Dir: e.IsDir, Link: e.IsLink, Size: e.Size,
			Perm: e.Perm, Sym: e.Sym, Owner: e.Owner, Group: e.Group, MTime: e.ModTime.Unix(),
		})
	}
	parent := ""
	if cur != "" {
		if parent = cleanRel(path.Dir(cur)); parent == "." {
			parent = ""
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":     cur,
		"parent":   parent,
		"atRoot":   cur == "",
		"crumbs":   buildCrumbs(cur),
		"entries":  items,
		"owners":   s.chownCandidateList(site),
		"canChown": !s.cfg.Dev,
		"counts":   map[string]int{"dirs": dirs, "files": files, "hidden": hidden},
	})
}

// chownCandidateSet is the SAFE set of names a file in this site may be handed
// to: the site's own system user and the web-server user. It deliberately
// excludes root, other tenants, and every service account — a tenant (or an
// admin acting on a tenant's files) must never be able to chown to an
// arbitrary or privileged owner through the panel.
func (s *Server) chownCandidateSet(site *store.Site) map[string]bool {
	m := map[string]bool{}
	if owner, err := s.store.UserByID(site.UserID); err == nil && owner.SystemUser != "" {
		m[owner.SystemUser] = true
	}
	if wu := s.cfg.WebServerUser(); wu != "" {
		m[wu] = true
	}
	return m
}

func (s *Server) chownCandidateList(site *store.Site) []string {
	set := s.chownCandidateSet(site)
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// postFilePermissions applies mode (chmod) and/or owner/group (chown) to one
// entry. Ownership targets are validated against chownCandidateSet, so no form
// value can aim an owner at root or another tenant.
func (s *Server) postFilePermissions(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	rel := path.Join(dir, name)
	if mode := strings.TrimSpace(r.FormValue("mode")); mode != "" {
		if err := fs.Chmod(rel, mode); err != nil {
			s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
			return
		}
	}
	owner := strings.TrimSpace(r.FormValue("owner"))
	group := strings.TrimSpace(r.FormValue("group"))
	if owner != "" || group != "" {
		// The candidate allowlist is enforced ALWAYS (even in dev) so a
		// disallowed owner is a hard error rather than a silent no-op; only the
		// actual chown syscall is skipped off-Linux.
		cands := s.chownCandidateSet(site)
		uid, gid := -1, -1 // -1 = leave unchanged (POSIX chown)
		if owner != "" {
			if !cands[owner] {
				s.filesRedirect(w, r, site.ID, dir, "err", "That owner is not allowed")
				return
			}
			if !s.cfg.Dev {
				u, err := osuser.Lookup(owner)
				if err != nil {
					s.filesRedirect(w, r, site.ID, dir, "err", "Owner not found on the system")
					return
				}
				uid, _ = strconv.Atoi(u.Uid)
			}
		}
		if group != "" {
			if !cands[group] {
				s.filesRedirect(w, r, site.ID, dir, "err", "That group is not allowed")
				return
			}
			if !s.cfg.Dev {
				g, err := osuser.LookupGroup(group)
				if err != nil {
					s.filesRedirect(w, r, site.ID, dir, "err", "Group not found on the system")
					return
				}
				gid, _ = strconv.Atoi(g.Gid)
			}
		}
		if !s.cfg.Dev {
			if err := fs.Chown(rel, uid, gid); err != nil {
				s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
				return
			}
		}
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", "Permissions updated for "+name)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// isAjax reports whether the request came from the explorer's fetch() calls
// (which set X-OPP-Ajax) rather than a plain browser form submit.
func isAjax(r *http.Request) bool { return r.Header.Get("X-OPP-Ajax") == "1" }

func (s *Server) getFileEdit(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	viewer := auth.UserFrom(r.Context())
	rel := cleanRel(r.FormValue("path"))
	content, err := fs.ReadText(rel)
	if err != nil {
		s.filesRedirect(w, r, site.ID, dirOf(rel), "err", userError(err))
		return
	}
	s.render.page(w, http.StatusOK, "fileedit", pageData{
		User: viewer, Active: "files",
		Data: fileEditVM{Site: site, Path: rel, Dir: dirOf(rel), Name: path.Base(rel), Content: content},
	})
}

func (s *Server) postFileSave(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	rel := cleanRel(r.FormValue("path"))
	if err := fs.WriteText(rel, normalizeNewlines(r.FormValue("content"))); err != nil {
		s.filesRedirect(w, r, site.ID, dirOf(rel), "err", userError(err))
		return
	}
	s.chownToSite(fs, site, rel)
	s.filesRedirect(w, r, site.ID, dirOf(rel), "msg", path.Base(rel)+" saved")
}

func (s *Server) postFileUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", "Upload too large or malformed")
		return
	}
	headers := r.MultipartForm.File["file"]
	if len(headers) == 0 {
		s.filesRedirect(w, r, site.ID, dir, "err", "No file provided")
		return
	}
	var saved []string
	for _, header := range headers {
		file, err := header.Open()
		if err != nil {
			continue
		}
		rel, err := fs.SaveUploadReader(dir, header.Filename, file)
		file.Close()
		if err != nil {
			s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
			return
		}
		s.chownToSite(fs, site, rel)
		saved = append(saved, path.Base(rel))
	}
	if len(saved) == 0 {
		s.filesRedirect(w, r, site.ID, dir, "err", "No file could be read from the upload")
		return
	}
	msg := "Uploaded " + saved[0]
	if len(saved) > 1 {
		msg = "Uploaded " + strconv.Itoa(len(saved)) + " files"
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", msg)
}

func (s *Server) postFileMkdir(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid folder name")
		return
	}
	rel := path.Join(dir, name)
	if err := fs.Mkdir(rel); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.chownToSite(fs, site, rel)
	s.filesRedirect(w, r, site.ID, dir, "msg", "Folder "+name+" created")
}

func (s *Server) postFileNew(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid file name")
		return
	}
	rel := path.Join(dir, name)
	if err := fs.CreateFile(rel); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.chownToSite(fs, site, rel)
	s.filesRedirect(w, r, site.ID, dir, "msg", "File "+name+" created")
}

func (s *Server) postFileDelete(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	if err := fs.Delete(path.Join(dir, name)); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", name+" deleted")
}

func (s *Server) postFileRename(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	newName := r.FormValue("new_name")
	if !validName(name) || !validName(newName) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	if err := fs.Rename(path.Join(dir, name), path.Join(dir, newName)); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", "Renamed to "+newName)
}

// postFileMove moves an entry into another directory within the same jail.
func (s *Server) postFileMove(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	dest := cleanRel(r.FormValue("dest")) // target directory, relative to the jail root
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	if err := fs.Rename(path.Join(dir, name), path.Join(dest, name)); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", name+" moved to /"+dest)
}

// postFileCopy duplicates an entry into another directory (blank = current).
// A same-directory copy gets a "-copy" suffix so it never collides.
func (s *Server) postFileCopy(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	dest := cleanRel(r.FormValue("dest"))
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	targetName := name
	if dest == dir {
		ext := path.Ext(name)
		targetName = strings.TrimSuffix(name, ext) + "-copy" + ext
	}
	target := path.Join(dest, targetName)
	if err := fs.CopyEntry(path.Join(dir, name), target); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.chownTreeToSite(fs, site, target)
	s.filesRedirect(w, r, site.ID, dir, "msg", "Copied "+name+" to /"+path.Join(dest, targetName))
}

// postFileZip archives the selected entries of the current directory.
func (s *Server) postFileZip(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	names, ok := selectedNames(r)
	if !ok {
		s.filesRedirect(w, r, site.ID, dir, "err", "Select at least one file or folder")
		return
	}
	archive := strings.TrimSpace(r.FormValue("archive"))
	if archive == "" {
		archive = "archive.zip"
	}
	if !strings.HasSuffix(archive, ".zip") {
		archive += ".zip"
	}
	if !validName(archive) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid archive name")
		return
	}
	target := path.Join(dir, archive)
	if err := fs.Zip(dir, names, target); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.chownToSite(fs, site, target)
	s.filesRedirect(w, r, site.ID, dir, "msg", "Created "+archive+" ("+strconv.Itoa(len(names))+" item(s))")
}

// postFileUnzip extracts a .zip into the current directory.
func (s *Server) postFileUnzip(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	created, err := fs.Unzip(path.Join(dir, name), dir)
	// Chown whatever WAS extracted even on a partial failure, so the tenant's
	// PHP can manage the files that did land. Resolve the tenant uid/gid ONCE
	// (it is loop-invariant) rather than per entry — an archive can hold
	// thousands of files.
	if uid, gid, ok := s.siteTenantIDs(site); ok {
		for _, rel := range created {
			_ = fs.Chown(rel, uid, gid)
		}
	}
	if err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", "Extracted "+name+" ("+strconv.Itoa(len(created))+" item(s))")
}

// postBulkDelete removes every selected entry of the current directory.
func (s *Server) postBulkDelete(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	names, ok := selectedNames(r)
	if !ok {
		s.filesRedirect(w, r, site.ID, dir, "err", "Select at least one file or folder")
		return
	}
	for _, name := range names {
		if err := fs.Delete(path.Join(dir, name)); err != nil {
			s.filesRedirect(w, r, site.ID, dir, "err", name+": "+userError(err))
			return
		}
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", strconv.Itoa(len(names))+" item(s) deleted")
}

// postBulkMove moves every selected entry into another directory.
func (s *Server) postBulkMove(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	dest := cleanRel(r.FormValue("dest"))
	names, ok := selectedNames(r)
	if !ok {
		s.filesRedirect(w, r, site.ID, dir, "err", "Select at least one file or folder")
		return
	}
	for _, name := range names {
		if err := fs.Rename(path.Join(dir, name), path.Join(dest, name)); err != nil {
			s.filesRedirect(w, r, site.ID, dir, "err", name+": "+userError(err))
			return
		}
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", strconv.Itoa(len(names))+" item(s) moved to /"+dest)
}

// selectedNames returns the validated multi-select checkbox values.
func selectedNames(r *http.Request) ([]string, bool) {
	_ = r.ParseForm()
	raw := r.Form["sel"]
	names := make([]string, 0, len(raw))
	for _, n := range raw {
		if validName(n) {
			names = append(names, n)
		}
	}
	return names, len(names) > 0
}

func (s *Server) postFileChmod(w http.ResponseWriter, r *http.Request) {
	fs, site, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	dir := cleanRel(r.FormValue("path"))
	name := r.FormValue("name")
	if !validName(name) {
		s.filesRedirect(w, r, site.ID, dir, "err", "Invalid name")
		return
	}
	if err := fs.Chmod(path.Join(dir, name), r.FormValue("mode")); err != nil {
		s.filesRedirect(w, r, site.ID, dir, "err", userError(err))
		return
	}
	s.filesRedirect(w, r, site.ID, dir, "msg", "Permissions updated for "+name)
}

func (s *Server) getFileDownload(w http.ResponseWriter, r *http.Request) {
	fs, _, ok := s.openFS(w, r)
	if !ok {
		return
	}
	defer fs.Close()
	fh, fi, err := fs.OpenRead(cleanRel(r.FormValue("path")))
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer fh.Close()
	// Force download and never let the browser MIME-sniff (an uploaded .html/
	// .svg served inline would run as script on the panel's own origin).
	w.Header().Set("Content-Disposition", contentDisposition(fi.Name()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), fh)
}

// contentDisposition builds a safe attachment header: an ASCII-sanitised
// quoted filename (control chars, quotes and backslashes stripped so the header
// value can't be broken out of) plus an RFC 5987 UTF-8 form for rich clients.
func contentDisposition(name string) string {
	ascii := strings.Map(func(rr rune) rune {
		if rr < 0x20 || rr == 0x7f || rr == '"' || rr == '\\' || rr >= 0x80 {
			return '_'
		}
		return rr
	}, name)
	if ascii == "" {
		ascii = "download"
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + url.PathEscape(name)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// chownToSite hands a panel-created path to the site's system user so the
// account's PHP (which runs as that user) can read/write it. No-op in dev or
// when the account has no system user.
func (s *Server) chownToSite(fs *filemanager.FS, site *store.Site, rel string) {
	if uid, gid, ok := s.siteTenantIDs(site); ok {
		_ = fs.Chown(rel, uid, gid)
	}
}

// chownTreeToSite is chownToSite for a whole subtree (copied folders).
func (s *Server) chownTreeToSite(fs *filemanager.FS, site *store.Site, rel string) {
	if uid, gid, ok := s.siteTenantIDs(site); ok {
		_ = fs.ChownTree(rel, uid, gid)
	}
}

func (s *Server) siteTenantIDs(site *store.Site) (uid, gid int, ok bool) {
	if s.cfg.Dev {
		return 0, 0, false
	}
	owner, err := s.store.UserByID(site.UserID)
	if err != nil || owner.SystemUser == "" {
		return 0, 0, false
	}
	u, err := osuser.Lookup(owner.SystemUser)
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// userError maps an internal filesystem error to a safe, generic message,
// logging the detail server-side. This avoids leaking absolute server paths
// (which raw os error strings contain) into the UI.
func userError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, filemanager.ErrOutsideJail):
		return "That path is not allowed"
	case errors.Is(err, filemanager.ErrTooLarge):
		return "File is too large to edit"
	case errors.Is(err, filemanager.ErrBinary):
		return "That file is not editable text"
	case errors.Is(err, filemanager.ErrIsDir):
		return "That is a directory"
	case errors.Is(err, filemanager.ErrArchiveTooBig):
		return "The archive is too large to extract on the server"
	case os.IsNotExist(err):
		return "No such file or folder"
	case os.IsExist(err):
		return "A file or folder with that name already exists"
	case os.IsPermission(err):
		return "Permission denied"
	}
	log.Printf("filemanager: %v", err)
	return "Operation failed"
}

// filesRedirect completes a file mutation. For the explorer's fetch() calls
// (X-OPP-Ajax) it answers JSON so the page can refresh in place; for a plain
// form submit it falls back to a Post/Redirect/Get with a flash.
func (s *Server) filesRedirect(w http.ResponseWriter, r *http.Request, siteID int64, dir, kind, msg string) {
	if isAjax(r) {
		if kind == "err" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{"msg": msg})
		}
		return
	}
	v := url.Values{}
	v.Set("site", strconv.FormatInt(siteID, 10))
	if dir != "" {
		v.Set("path", dir)
	}
	if msg != "" {
		v.Set(kind, msg)
	}
	http.Redirect(w, r, "/files?"+v.Encode(), http.StatusSeeOther)
}

// cleanRel normalises a user path to a slash-relative form with no leading
// slash or ".." (final jailing still happens in the filemanager).
func cleanRel(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

func dirOf(rel string) string {
	d := path.Dir(rel)
	if d == "." || d == "/" {
		return ""
	}
	return d
}

func buildCrumbs(cur string) []crumb {
	crumbs := []crumb{{Name: "home", Path: ""}}
	if cur == "" {
		return crumbs
	}
	acc := ""
	for _, part := range strings.Split(cur, "/") {
		if part == "" {
			continue
		}
		acc = path.Join(acc, part)
		crumbs = append(crumbs, crumb{Name: part, Path: acc})
	}
	return crumbs
}

// validName rejects empty names and anything with path separators or dot-dots,
// so entry actions stay within the current directory.
func validName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
