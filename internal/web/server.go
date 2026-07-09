// Package web is Open ProPanel's HTTP layer: routing, middleware and the HTMX-driven
// handlers that render the Tailwind UI. All state-changing routes use the
// Post/Redirect/Get pattern so the UI works with or without JavaScript.
package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/domains"
	"github.com/openpropanel/openpropanel/internal/mariadb"
	"github.com/openpropanel/openpropanel/internal/php"
	"github.com/openpropanel/openpropanel/internal/phpmyadmin"
	"github.com/openpropanel/openpropanel/internal/store"
	"github.com/openpropanel/openpropanel/internal/sysuser"
)

// Server bundles dependencies for the HTTP handlers.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	auth    *auth.Manager
	domains *domains.Service
	php     *php.Manager
	sysuser *sysuser.Manager
	mariadb *mariadb.Manager
	pma     *phpmyadmin.Manager
	render   *renderer
	cfgPath  string
	login    *loginLimiter
	pmaLogin *loginLimiter // throttles phpMyAdmin's own login POSTs

	// short-TTL cache so rapid dashboard polling coalesces into one sample
	// instead of spawning subprocesses per request.
	statsMu    sync.Mutex
	statsCache dashboardVM
	statsAt    time.Time
}

// New constructs the web server.
func New(cfg *config.Config, s *store.Store, a *auth.Manager, d *domains.Service, p *php.Manager, su *sysuser.Manager, mdb *mariadb.Manager, pma *phpmyadmin.Manager, cfgPath string) (*Server, error) {
	r, err := newRenderer()
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, store: s, auth: a, domains: d, php: p, sysuser: su, mariadb: mdb, pma: pma, render: r, cfgPath: cfgPath, login: newLoginLimiter(), pmaLogin: newLoginLimiter()}, nil
}

// Handler builds the full middleware/route tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public assets and auth endpoints.
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	// Authenticated application routes live behind the auth middleware.
	app := http.NewServeMux()
	app.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})
	app.HandleFunc("GET /setup", s.getSetup)
	app.HandleFunc("POST /setup", s.postSetup)
	app.HandleFunc("GET /dashboard", s.getDashboard)
	app.HandleFunc("GET /dashboard/stats", s.getStats)
	app.HandleFunc("POST /services/{unit}/{action}", s.postService)

	app.HandleFunc("GET /sites", s.getSites)
	app.HandleFunc("POST /sites", s.postCreateSite)
	app.HandleFunc("POST /sites/{id}/delete", s.postDeleteSite)
	app.HandleFunc("POST /sites/{id}/php", s.postChangePHP)
	app.HandleFunc("POST /sites/{id}/ssl", s.postToggleSSL)
	app.HandleFunc("POST /sites/{id}/subdomains", s.postAddSubdomain)
	app.HandleFunc("POST /sites/scan", s.postScanSites)
	app.HandleFunc("POST /sites/{id}/adopt", s.postAdoptSite)
	app.HandleFunc("POST /sites/{id}/mapping", s.postMapSite)

	// GitHub deploy. {id} on /projects is the project's main site; {id} on
	// /repos is the repo. Every handler is owner-or-admin gated.
	app.HandleFunc("POST /projects/{id}/repo", s.postLinkRepo)
	app.HandleFunc("POST /projects/{id}/repo/delete", s.postUnlinkRepo)
	app.HandleFunc("POST /projects/{id}/deploy", s.postDeployProject)
	app.HandleFunc("POST /repos/{id}/clone", s.postCloneRepo)
	app.HandleFunc("POST /repos/{id}/verify", s.postVerifyRepo)
	app.HandleFunc("GET /repos/{id}/tree", s.getRepoTree)

	app.HandleFunc("GET /databases", s.getDatabases)
	app.HandleFunc("POST /databases", s.postCreateDatabase)
	app.HandleFunc("POST /databases/{id}/delete", s.postDeleteDatabase)
	app.HandleFunc("POST /db-users", s.postCreateDBUser)
	app.HandleFunc("POST /db-users/{id}/delete", s.postDeleteDBUser)
	app.HandleFunc("POST /db-users/{id}/password", s.postResetDBUserPassword)
	app.HandleFunc("POST /db-grants", s.postGrant)
	app.HandleFunc("POST /db-grants/revoke", s.postRevoke)

	// phpMyAdmin: install is admin-only; the app itself is served (behind the
	// panel session) to any authenticated user, who then authenticates again to
	// MariaDB with their own credentials. The more-specific /phpmyadmin/install
	// pattern takes precedence over the /phpmyadmin/ subtree.
	app.Handle("POST /phpmyadmin/install", auth.RequireAdmin(http.HandlerFunc(s.postInstallPMA)))
	app.HandleFunc("/phpmyadmin/", s.servePMA)

	app.HandleFunc("GET /files", s.getFiles)
	app.HandleFunc("GET /files/edit", s.getFileEdit)
	app.HandleFunc("GET /files/download", s.getFileDownload)
	app.HandleFunc("POST /files/save", s.postFileSave)
	app.HandleFunc("POST /files/upload", s.postFileUpload)
	app.HandleFunc("POST /files/mkdir", s.postFileMkdir)
	app.HandleFunc("POST /files/new", s.postFileNew)
	app.HandleFunc("POST /files/delete", s.postFileDelete)
	app.HandleFunc("POST /files/rename", s.postFileRename)
	app.HandleFunc("POST /files/chmod", s.postFileChmod)

	// Admin-only routes.
	app.Handle("GET /users", auth.RequireAdmin(http.HandlerFunc(s.getUsers)))
	app.Handle("POST /users", auth.RequireAdmin(http.HandlerFunc(s.postCreateUser)))
	app.Handle("POST /users/{id}/delete", auth.RequireAdmin(http.HandlerFunc(s.postDeleteUser)))
	app.Handle("GET /settings", auth.RequireAdmin(http.HandlerFunc(s.getSettings)))
	app.Handle("POST /settings", auth.RequireAdmin(http.HandlerFunc(s.postSettings)))
	app.Handle("POST /settings/panel-cert", auth.RequireAdmin(http.HandlerFunc(s.postPanelCert)))
	app.Handle("POST /settings/webserver", auth.RequireAdmin(http.HandlerFunc(s.postWebServer)))

	mux.Handle("/", s.auth.Middleware(s.setupGate(app)))

	return logMiddleware(securityHeaders(auth.SameOrigin(mux)))
}

// Start runs the HTTP server until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Generous write timeout: enabling SSL shells out to certbot, which can
		// take longer than an ordinary request.
		WriteTimeout: 180 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	// Periodically garbage-collect expired sessions.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = s.store.DeleteExpiredSessions()
			}
		}
	}()

	if s.cfg.TLSEnabled {
		cm := newCertManager(s.cfg)
		if err := cm.ensureBootstrap(); err != nil {
			return fmt.Errorf("prepare TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cm.GetCertificate,
		}
		log.Printf("Open ProPanel listening on https://%s", s.cfg.ListenAddr)
		// Cert files are supplied via GetCertificate, so pass empty filenames.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	log.Printf("Open ProPanel listening on http://%s", s.cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
