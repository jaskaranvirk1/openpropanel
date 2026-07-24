package web

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openpropanel/openpropanel/internal/ai"
	"github.com/openpropanel/openpropanel/internal/auth"
)

// assistantVM is the AI assistant chat page's view model.
type assistantVM struct {
	Configured bool
	Provider   string
	Model      string
}

// getAssistant renders the AI deployment assistant chat page (admin-only).
func (s *Server) getAssistant(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	provider, model, keySet := s.cfg.AISettings()
	s.render.page(w, http.StatusOK, "assistant", pageData{
		User: u, Active: "assistant",
		Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"),
		Data: assistantVM{
			Configured: keySet && provider == "claude" && strings.TrimSpace(model) != "",
			Provider:   provider, Model: model,
		},
	})
}

// postAssistantChat handles one chat turn: {conv_id, message} in, the assistant
// reply (or an error) out, as JSON. The agentic loop (which executes real
// deployment actions) runs server-side under a bounded deadline.
func (s *Server) postAssistantChat(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	var req struct {
		ConvID  string `json:"conv_id"`
		Message string `json:"message"`
	}
	// Cap the request body: a chat message is small.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Could not read the message."})
		return
	}

	// Namespace the conversation by the acting user so transcripts can never be
	// addressed across accounts, even if the assistant is later opened to users.
	convID := strconv.FormatInt(u.ID, 10) + ":" + sanitizeConvID(req.ConvID)

	// Bound the whole tool-use loop below the server's write timeout so a long
	// run returns a partial answer rather than a dropped connection.
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()

	reply, err := s.assistant.Chat(ctx, u, convID, req.Message)
	if err != nil {
		log.Printf("assistant chat error [user %d]: %v", u.ID, err)
		status := http.StatusBadGateway
		if errors.Is(err, ai.ErrNotConfigured) {
			status = http.StatusBadRequest
		}
		// The agent's errors are written to be user-safe (no secrets, no raw
		// command output), and this endpoint is admin-only.
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, reply)
}

// postSettingsAI saves the AI assistant configuration (admin-only). The API key
// is a secret: a blank key field keeps the stored key; "clear_key" removes it.
// The key is never echoed back to any page.
func (s *Server) postSettingsAI(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.FormValue("ai_provider"))
	if provider == "" {
		provider = "claude"
	}
	if provider != "claude" {
		redirect(w, r, "/settings", "err", "Only the Claude (Anthropic) provider is supported right now.")
		return
	}
	model := strings.TrimSpace(r.FormValue("ai_model"))
	if model == "" {
		model = ai.DefaultModel
	}
	key := strings.TrimSpace(r.FormValue("ai_api_key"))
	clearKey := r.FormValue("clear_key") == "1"

	s.cfg.SetAI(provider, model, key, clearKey)
	if err := s.cfg.Save(s.cfgPath); err != nil {
		redirect(w, r, "/settings", "err", "Could not save AI settings: "+err.Error())
		return
	}
	msg := "AI assistant settings saved"
	if clearKey {
		msg = "AI API key removed"
	}
	redirect(w, r, "/settings", "msg", msg)
}

// sanitizeConvID keeps only a bounded, safe conversation identifier from client
// input (it is only a map key, but stay strict).
func sanitizeConvID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 64 {
		id = id[:64]
	}
	var b strings.Builder
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}
