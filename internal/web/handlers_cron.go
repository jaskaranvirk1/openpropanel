package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/openpropanel/openpropanel/internal/auth"
	"github.com/openpropanel/openpropanel/internal/cron"
	"github.com/openpropanel/openpropanel/internal/store"
)

// cronPreset is a "Common Settings" entry that pre-fills the schedule fields
// (mirrors cPanel's Cron Jobs page).
type cronPreset struct{ Label, Minute, Hour, Dom, Month, Dow string }

func cronPresets() []cronPreset {
	return []cronPreset{
		{"Every minute", "*", "*", "*", "*", "*"},
		{"Every 5 minutes", "*/5", "*", "*", "*", "*"},
		{"Every 15 minutes", "*/15", "*", "*", "*", "*"},
		{"Every 30 minutes", "*/30", "*", "*", "*", "*"},
		{"Once an hour", "0", "*", "*", "*", "*"},
		{"Twice a day", "0", "0,12", "*", "*", "*"},
		{"Once a day (midnight)", "0", "0", "*", "*", "*"},
		{"Once a week (Sun)", "0", "0", "*", "*", "0"},
		{"Once a month (1st)", "0", "0", "1", "*", "*"},
	}
}

type cronRow struct {
	Job       *store.CronJob
	OwnerName string
}

type cronVM struct {
	Rows       []cronRow
	IsAdmin    bool
	Users      []*store.User
	CurrentUID int64
	Presets    []cronPreset
}

// getCron lists the caller's cron jobs (admins see everyone's) + the create form.
func (s *Server) getCron(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	isAdmin := viewer.Role == store.RoleAdmin

	names := map[int64]string{viewer.ID: viewer.Username}
	var jobs []*store.CronJob
	var err error
	if isAdmin {
		jobs, err = s.store.ListCronJobsAll()
		if users, e := s.store.ListUsers(); e == nil {
			for _, u := range users {
				names[u.ID] = u.Username
			}
		}
	} else {
		jobs, err = s.store.ListCronJobsByUser(viewer.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]cronRow, 0, len(jobs))
	for _, j := range jobs {
		rows = append(rows, cronRow{Job: j, OwnerName: names[j.UserID]})
	}
	vm := cronVM{Rows: rows, IsAdmin: isAdmin, CurrentUID: viewer.ID, Presets: cronPresets()}
	if isAdmin {
		vm.Users, _ = s.store.ListUsers()
	}
	s.render.page(w, http.StatusOK, "cron", pageData{
		User: viewer, Active: "cron",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: vm,
	})
}

// postCreateCron validates + stores a job, then rewrites the owner's crontab.
func (s *Server) postCreateCron(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	owner := viewer.ID
	if viewer.Role == store.RoleAdmin {
		if v := r.FormValue("owner_id"); v != "" {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				owner = id
			}
		}
	}
	f := store.CronJob{
		UserID: owner,
		Minute: r.FormValue("minute"), Hour: r.FormValue("hour"), Dom: r.FormValue("dom"),
		Month: r.FormValue("month"), Dow: r.FormValue("dow"),
	}
	for _, fld := range []string{f.Minute, f.Hour, f.Dom, f.Month, f.Dow} {
		if !cron.ValidField(fld) {
			redirect(w, r, "/cron", "err", "Invalid schedule field "+strconv.Quote(fld)+" — use cron syntax like *, */5, 0-30, 1,15.")
			return
		}
	}
	cmd, err := cron.CleanCommand(r.FormValue("command"))
	if err != nil {
		redirect(w, r, "/cron", "err", s.opErr(r, err))
		return
	}
	f.Command = cmd
	if _, err := s.store.CreateCronJob(&f); err != nil {
		redirect(w, r, "/cron", "err", s.opErr(r, err))
		return
	}
	if err := s.syncCron(r.Context(), owner); err != nil {
		// crond rejected the resulting crontab (e.g. an out-of-range value). Roll
		// the job back so it can't persist and wedge every later sync, and restore
		// the previous good crontab.
		_ = s.store.DeleteCronJob(f.ID)
		_ = s.syncCron(r.Context(), owner)
		redirect(w, r, "/cron", "err", "That job was rejected by cron — check the schedule: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/cron", "msg", "Cron job added")
}

// postDeleteCron removes a job (owner or admin) and rewrites the crontab.
func (s *Server) postDeleteCron(w http.ResponseWriter, r *http.Request) {
	viewer := auth.UserFrom(r.Context())
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	job, err := s.store.CronJobByID(id)
	if err != nil {
		redirect(w, r, "/cron", "err", "Cron job not found")
		return
	}
	if job.UserID != viewer.ID && viewer.Role != store.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteCronJob(id); err != nil {
		redirect(w, r, "/cron", "err", s.opErr(r, err))
		return
	}
	if err := s.syncCron(r.Context(), job.UserID); err != nil {
		redirect(w, r, "/cron", "err", "Job removed but updating the crontab failed: "+s.opErr(r, err))
		return
	}
	redirect(w, r, "/cron", "msg", "Cron job removed")
}

// syncCron rewrites an account's crontab from its stored jobs, running them as
// its (JIT-provisioned) non-root system user.
func (s *Server) syncCron(ctx context.Context, userID int64) error {
	systemUser, err := s.domains.EnsureTenantUser(ctx, userID)
	if err != nil {
		return err
	}
	jobs, err := s.store.ListCronJobsByUser(userID)
	if err != nil {
		return err
	}
	cj := make([]cron.Job, 0, len(jobs))
	for _, j := range jobs {
		cj = append(cj, cron.Job{Minute: j.Minute, Hour: j.Hour, Dom: j.Dom, Month: j.Month, Dow: j.Dow, Command: j.Command})
	}
	return s.cron.Sync(ctx, systemUser, cj)
}
