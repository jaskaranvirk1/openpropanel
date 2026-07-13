package domains

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/openpropanel/openpropanel/internal/store"
)

// createAppWithPort allocates a free port and inserts the app row while holding
// appMu, so the free-port scan and the insert are one critical section — two
// concurrent enable-proxy calls can't both pick the same lowest-free port (the
// loser would otherwise hit a raw apps.port UNIQUE error). The UNIQUE constraint
// remains the final backstop.
func (s *Service) createAppWithPort(siteID int64, runtime, startCmd, env string, managed bool) (*store.App, error) {
	s.appMu.Lock()
	defer s.appMu.Unlock()
	port, err := s.freePortLocked()
	if err != nil {
		return nil, err
	}
	return s.store.CreateApp(&store.App{
		SiteID: siteID, Port: port, Runtime: runtime,
		StartCommand: startCmd, Managed: managed, Env: env,
	})
}

// freePortLocked returns the lowest free port in the configured range that is
// not already assigned to an app and not currently listening. The caller MUST
// hold appMu (so the port stays free until the app row is inserted).
func (s *Service) freePortLocked() (int, error) {
	used, err := s.store.UsedPorts()
	if err != nil {
		return 0, err
	}
	lo, hi := s.cfg.AppPortMin, s.cfg.AppPortMax
	if lo <= 0 {
		lo = 3000
	}
	if hi < lo {
		hi = 3999
	}
	for p := lo; p <= hi; p++ {
		if used[p] {
			continue
		}
		if s.cfg.Dev || portFree(p) {
			return p, nil
		}
	}
	return 0, errors.New("no free application port in the configured range")
}

// portFree reports whether nothing is already listening on 127.0.0.1:p.
func portFree(p int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// SetProxyApp switches a managed site to reverse-proxy mode: allocate/keep a
// port, persist the app config, flip WebMode=proxy, render the proxy vhost, and
// (when managed) install + start the systemd unit that runs the start command
// as the site's non-root tenant user.
func (s *Service) SetProxyApp(ctx context.Context, siteID int64, runtime, startCmd, env string, managed bool) (*store.App, error) {
	site, err := s.store.SiteByID(siteID)
	if err != nil {
		return nil, err
	}
	if site.Source != store.SourceManaged {
		return nil, errImportedReadOnly
	}
	owner, err := s.store.UserByID(site.UserID)
	if err != nil {
		return nil, errors.New("owner account not found")
	}
	// A managed app runs a process — it must have a non-root tenant user, exactly
	// like git deploys (tenantIDs refuses uid/gid 0), and needs a command to run.
	// Validate BEFORE any state mutation so a bad request can't flip a working
	// site into a broken (502-ing) proxy and only then error out.
	if managed {
		if _, _, err := s.tenantIDs(site.UserID); err != nil {
			return nil, err
		}
		if strings.TrimSpace(startCmd) == "" {
			return nil, errors.New("a start command is required to run the app")
		}
	}

	app, err := s.store.AppBySite(siteID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		app, err = s.createAppWithPort(siteID, runtime, startCmd, env, managed)
		if err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := s.store.UpdateApp(app.ID, runtime, startCmd, env, managed); err != nil {
			return nil, err
		}
		app.Runtime, app.StartCommand, app.Env, app.Managed = runtime, startCmd, env, managed
	}

	if err := s.store.SetSiteServe(siteID, site.DocRoot, store.WebModeProxy); err != nil {
		return nil, err
	}
	site.WebMode = store.WebModeProxy
	if err := s.renderVHost(site); err != nil {
		return nil, err
	}
	if err := s.web().Apply(ctx); err != nil {
		return nil, err
	}

	if managed {
		if err := s.appserver.Configure(ctx, app, site, owner.SystemUser); err != nil {
			_ = s.store.SetAppStatus(app.ID, "error")
			return nil, err
		}
		_ = s.store.SetAppStatus(app.ID, "running")
	} else {
		_ = s.appserver.Remove(ctx, site.Domain)
		_ = s.store.SetAppStatus(app.ID, "unmanaged")
	}
	return app, nil
}

// removeAppFor tears down a site's app unit and drops its row (freeing the
// port). Called when a site leaves proxy mode or is deleted.
func (s *Service) removeAppFor(ctx context.Context, site *store.Site) {
	app, err := s.store.AppBySite(site.ID)
	if err != nil {
		return
	}
	_ = s.appserver.Remove(ctx, site.Domain)
	_ = s.store.DeleteApp(app.ID)
}

func (s *Service) appAction(ctx context.Context, siteID int64, action string) error {
	site, err := s.store.SiteByID(siteID)
	if err != nil {
		return err
	}
	app, err := s.store.AppBySite(siteID)
	if err != nil {
		return errors.New("this site has no app configured")
	}
	if !app.Managed {
		return errors.New("this app is not managed by the panel")
	}
	switch action {
	case "start":
		return s.appserver.Start(ctx, site.Domain)
	case "stop":
		return s.appserver.Stop(ctx, site.Domain)
	case "restart":
		return s.appserver.Restart(ctx, site.Domain)
	}
	return errors.New("unknown action")
}

// StartApp / StopApp / RestartApp control a site's managed app process.
func (s *Service) StartApp(ctx context.Context, siteID int64) error {
	return s.appAction(ctx, siteID, "start")
}
func (s *Service) StopApp(ctx context.Context, siteID int64) error {
	return s.appAction(ctx, siteID, "stop")
}
func (s *Service) RestartApp(ctx context.Context, siteID int64) error {
	return s.appAction(ctx, siteID, "restart")
}

// AppFor returns a site's app row, or nil.
func (s *Service) AppFor(siteID int64) *store.App {
	if app, err := s.store.AppBySite(siteID); err == nil {
		return app
	}
	return nil
}

// AppStatus reports whether a site's app unit is active/enabled.
func (s *Service) AppStatus(ctx context.Context, siteID int64) (active, enabled bool) {
	site, err := s.store.SiteByID(siteID)
	if err != nil {
		return false, false
	}
	return s.appserver.Status(ctx, site.Domain)
}

// AppLogs returns the last n journald lines for a site's app.
func (s *Service) AppLogs(ctx context.Context, siteID int64, n int) (string, error) {
	site, err := s.store.SiteByID(siteID)
	if err != nil {
		return "", err
	}
	return s.appserver.Logs(ctx, site.Domain, n)
}

// ReconcileApps regenerates and restarts every managed app unit at startup, so
// units survive a panel upgrade or a wiped /etc/systemd (the DB is the source
// of truth).
func (s *Service) ReconcileApps(ctx context.Context) {
	apps, err := s.store.ListManagedApps()
	if err != nil {
		return
	}
	for _, app := range apps {
		site, err := s.store.SiteByID(app.SiteID)
		if err != nil || site.Source != store.SourceManaged {
			continue
		}
		owner, err := s.store.UserByID(site.UserID)
		if err != nil || owner.SystemUser == "" {
			continue
		}
		if _, _, err := s.tenantIDs(site.UserID); err != nil {
			continue
		}
		_ = s.appserver.Configure(ctx, app, site, owner.SystemUser)
	}
}
