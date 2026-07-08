package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
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
	navActive = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium bg-indigo-500/10 text-indigo-300 ring-1 ring-inset ring-indigo-500/20"
	navIdle   = "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-white/5 transition-colors"
)

var funcMap = template.FuncMap{
	"hbytes": humanBytes,
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
			return "bg-rose-500"
		case pct >= 70:
			return "bg-amber-400"
		default:
			return "bg-indigo-500"
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
}

func newRenderer() (*renderer, error) {
	r := &renderer{pages: map[string]*template.Template{}, roots: map[string]string{}}

	// Base set carries shared partials and helper funcs; each page clones it.
	base := template.New("openpropanel").Funcs(funcMap)
	base, err := base.ParseFS(templatesFS, "templates/partials.html")
	if err != nil {
		return nil, err
	}

	appPages := []string{"dashboard", "sites", "databases", "users", "settings", "files", "fileedit"}
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

	// Login is a standalone full page (no app shell / sidebar).
	loginClone, err := base.Clone()
	if err != nil {
		return nil, err
	}
	loginT, err := loginClone.ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	r.pages["login"] = loginT
	r.roots["login"] = "login.html"

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
