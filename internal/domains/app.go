package domains

import (
	"context"
	"errors"
	"strings"

	"github.com/openpropanel/openpropanel/internal/store"
)

// SetProxyApp switches a site to reverse-proxy mode and runs its app: it persists
// the app config, flips WebMode=proxy, renders the proxy vhost (pointed at the
// app's private unix socket), then installs + starts the systemd unit that runs
// the start command as the site's non-root tenant user. Every proxy app is
// panel-managed — a non-root tenant user and a start command are required (the
// socket-isolation model has no place for an unsupervised, port-based app).
func (s *Service) SetProxyApp(ctx context.Context, siteID int64, runtime, startCmd, env string) (*store.App, error) {
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
	// Validate BEFORE any state mutation so a bad request can't flip a working
	// site into a broken (502-ing) proxy and only then error out: the app must
	// have a non-root tenant user (like git deploys — tenantIDs refuses uid/gid 0)
	// and a command to run.
	if _, _, err := s.tenantIDs(site.UserID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(startCmd) == "" {
		return nil, errors.New("a start command is required to run the app")
	}

	app, err := s.store.AppBySite(siteID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// port is a legacy NOT NULL UNIQUE column; the socket addresses the app now,
		// so store the (unique) site id in it as an inert value.
		app, err = s.store.CreateApp(&store.App{
			SiteID: siteID, Port: int(siteID), Runtime: runtime,
			StartCommand: startCmd, Managed: true, Env: env,
		})
		if err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := s.store.UpdateApp(app.ID, runtime, startCmd, env, true); err != nil {
			return nil, err
		}
		app.Runtime, app.StartCommand, app.Env, app.Managed = runtime, startCmd, env, true
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

	if err := s.appserver.Configure(ctx, app, site, owner.SystemUser); err != nil {
		_ = s.store.SetAppStatus(app.ID, "error")
		return nil, err
	}
	_ = s.store.SetAppStatus(app.ID, "running")
	return app, nil
}

// removeAppFor tears down a site's app unit + socket dir and drops its row.
// Called when a site leaves proxy mode or is deleted.
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

// ReconcileApps regenerates and restarts every managed app unit at startup (so
// units + socket dirs survive a panel upgrade, a wiped /etc/systemd, or a tmpfs
// reboot — the DB is the source of truth), then re-renders managed vhosts so the
// on-disk web-server config matches the DB. The vhost re-render is what carries
// an upgrade across a transport change: a v0.11.0 proxy site's vhost still points
// at a now-dead TCP port until it is rewritten to the app's unix socket, and a
// site the migration reverted from a retired unmanaged proxy needs its file-mode
// vhost written. Best-effort and per-item so one bad site can't abort the rest.
func (s *Service) ReconcileApps(ctx context.Context) {
	if apps, err := s.store.ListManagedApps(); err == nil {
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
	sites, err := s.store.ListSites()
	if err != nil {
		return
	}
	rendered := false
	for _, site := range sites {
		if site.Source != store.SourceManaged {
			continue // imported sites are read-only until adopted
		}
		if err := s.renderVHost(site); err == nil {
			rendered = true
		}
	}
	if rendered {
		_ = s.web().Apply(ctx)
	}
}
