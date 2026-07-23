package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/store"
)

// Embedded assets: the whole UI ships inside the single binary.
//
//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// pageData wraps every full-page render with the context the layout needs.
type pageData struct {
	User   *store.User
	Active string // nav item to highlight
	Flash  string // success message
	Error  string // error message
	Data   any    // page-specific view model
}

// renderer holds one parsed template set per page.
type renderer struct {
	pages map[string]*template.Template
	roots map[string]string // page -> root template file to execute
}

// Nav link classes. These live in Go (not just HTML) so the Tailwind content
// scanner must include ./internal/web/**/*.go — see tailwind.config.js.
const (
	navActive = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium bg-blue-50 text-blue-700"
	navIdle   = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-zinc-500 hover:text-zinc-900 hover:bg-zinc-100 transition-colors"
)

var funcMap = template.FuncMap{
	// dict builds a map from alternating key/value args, so a sub-template can be
	// called with several named values: {{template "row" (dict "S" .Site "R" $)}}.
	"dict": func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				m[k] = kv[i+1]
			}
		}
		return m
	},
	"shortpath": shortPath,
	"hasSuffix": strings.HasSuffix,
	"hbytes":    humanBytes,
	"hsize": func(n int64) string {
		if n < 0 {
			n = 0
		}
		return humanBytes(uint64(n))
	},
	"hdur": humanDuration,
	"f1":     func(v float64) string { return fmt.Sprintf("%.1f", v) },
	"pct":    func(v float64) string { return fmt.Sprintf("%.0f%%", v) },
	"navClass": func(active, name string) string {
		if active == name {
			return navActive
		}
		return navIdle
	},
	// barClass picks a colour for a usage meter based on how full it is.
	"barClass": func(pct float64) string {
		switch {
		case pct >= 90:
			return "bg-red-500"
		case pct >= 70:
			return "bg-amber-500"
		default:
			return "bg-blue-600"
		}
	},
	// barWidth returns a clamped, pre-sanitised CSS width for a meter fill.
	"barWidth": func(pct float64) template.CSS {
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		return template.CSS(fmt.Sprintf("width:%.1f%%", pct))
	},
	// since renders a coarse "time ago" for a Unix-seconds timestamp (0 = "").
	"since": since,
}

// since formats a Unix-seconds timestamp as a coarse relative time.
func since(unix int64) string {
	if unix <= 0 {
		return ""
	}
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func newRenderer() (*renderer, error) {
	r := &renderer{pages: map[string]*template.Template{}, roots: map[string]string{}}

	// Base set carries shared partials and helper funcs; each page clones it.
	base := template.New("openpropanel").Funcs(funcMap)
	base, err := base.ParseFS(templatesFS, "templates/partials.html")
	if err != nil {
		return nil, err
	}

	appPages := []string{"dashboard", "domains", "domain", "domain_new", "databases", "cron", "users", "settings", "files", "fileedit"}
	for _, p := range appPages {
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		t, err := clone.ParseFS(templatesFS, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		r.pages[p] = t
		r.roots[p] = "layout.html"
	}

	// Login and the first-login setup wizard are standalone full pages (no app
	// shell / sidebar).
	for _, p := range []string{"login", "setup"} {
		clone, err := base.Clone()
		if err != nil {
			return nil, err
		}
		t, err := clone.ParseFS(templatesFS, "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		r.pages[p] = t
		r.roots[p] = p + ".html"
	}

	return r, nil
}

// page renders a full page with the app layout.
func (r *renderer) page(w http.ResponseWriter, status int, name string, pd pageData) {
	t, ok := r.pages[name]
	if !ok {
		http.Error(w, "unknown page: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, r.roots[name], pd); err != nil {
		// Response is already partially written; log-worthy but nothing else to do.
		fmt.Printf("render %s: %v\n", name, err)
	}
}

// fragment renders a single named sub-template (for HTMX partial swaps).
func (r *renderer) fragment(w http.ResponseWriter, page, def string, data any) {
	t, ok := r.pages[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, def, data); err != nil {
		fmt.Printf("render fragment %s/%s: %v\n", page, def, err)
	}
}

// staticHandler serves the embedded /static assets.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embed path is a compile-time constant; cannot fail at runtime
	}
	return http.FileServerFS(sub)
}

// shortPath abbreviates a long doc-root path for display, keeping the last two
// components (e.g. /var/www/x/frontend/dist/browser -> …/dist/browser).
func shortPath(p string) string {
	p = strings.TrimRight(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) <= 4 {
		return p
	}
	return "…/" + strings.Join(parts[len(parts)-2:], "/")
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}
