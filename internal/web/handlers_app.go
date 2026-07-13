package web

import "net/http"

// postSetApp switches a domain to reverse-proxy mode and configures its app
// (runtime, start command, env, managed).
func (s *Server) postSetApp(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	_, err := s.domains.SetProxyApp(r.Context(), site.ID,
		r.FormValue("runtime"), r.FormValue("start_command"), r.FormValue("env"))
	if err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", site.Domain+" is now served by its app")
}

// postAppAction start|stop|restart a site's managed app.
func (s *Server) postAppAction(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	var err error
	switch r.PathValue("action") {
	case "start":
		err = s.domains.StartApp(r.Context(), site.ID)
	case "stop":
		err = s.domains.StopApp(r.Context(), site.ID)
	case "restart":
		err = s.domains.RestartApp(r.Context(), site.ID)
	default:
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.backRedirect(w, r, "err", s.opErr(r, err))
		return
	}
	s.backRedirect(w, r, "msg", "App "+r.PathValue("action")+"ed")
}

// getAppLogs returns the app's recent journald output as plain text.
func (s *Server) getAppLogs(w http.ResponseWriter, r *http.Request) {
	site, ok := s.authorizeSite(w, r)
	if !ok {
		return
	}
	out, err := s.domains.AppLogs(r.Context(), site.ID, 200)
	if err != nil {
		out = "Could not read logs."
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(out))
}

// appRuntimes are the runtime labels offered in the UI.
func appRuntimes() []string { return []string{"node", "python", "custom"} }
