// Package ai implements Open ProPanel's optional AI deployment assistant: a
// chat agent that drives the panel's existing deployment operations (create a
// domain, connect a GitHub repo, map a monorepo subfolder, build, deploy,
// enable SSL) as tool calls, so an operator can ask for a deployment in plain
// language instead of clicking through the UI.
//
// The only supported provider today is Claude (Anthropic). We talk to the
// Messages API over net/http directly — the panel deliberately carries no
// third-party API SDKs, and every outbound call in the codebase is plain
// net/http, so the outbound surface stays small and auditable.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	messagesURL      = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"

	// maxRespBytes bounds a single API response body so a pathological reply
	// cannot exhaust the root panel's memory.
	maxRespBytes = 8 << 20 // 8 MB

	// DefaultModel is used when the operator has not typed a model name. It is
	// the current flagship; the operator may override it in Settings.
	DefaultModel = "claude-opus-4-8"

	// perCallTimeout bounds a single Messages API round trip.
	perCallTimeout = 90 * time.Second
)

// toolSpec is a tool advertised to the model (name + JSON-Schema input).
type toolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// wireMessage is one conversation turn on the wire. Content is kept as raw JSON
// so an assistant turn (which may contain tool_use blocks) can be echoed back to
// the API byte-for-byte on the next request, exactly as the API requires.
type wireMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type messagesRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	System    string        `json:"system,omitempty"`
	Messages  []wireMessage `json:"messages"`
	Tools     []toolSpec    `json:"tools,omitempty"`
}

// contentBlock is one block of an assistant response. We only ever read text and
// tool_use blocks (thinking is not requested), but the raw response content is
// preserved verbatim in the transcript, so a future block type is never lost.
type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// toolResultBlock is a single tool result we send back in a user turn.
type toolResultBlock struct {
	Type      string `json:"type"` // always "tool_result"
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type textBlock struct {
	Type string `json:"type"` // always "text"
	Text string `json:"text"`
}

type messagesResponse struct {
	Type       string          `json:"type"` // "message" or "error"
	Content    json.RawMessage `json:"content"`
	StopReason string          `json:"stop_reason"`
	Model      string          `json:"model"`
	Error      *apiError       `json:"error"`
}

type apiError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// client is a thin Messages API caller bound to one API key.
type client struct {
	key  string
	http *http.Client
}

func newClient(key string) *client {
	return &client{key: key, http: &http.Client{Timeout: perCallTimeout}}
}

// call performs one Messages API request. It returns a caller-safe error for
// transport/HTTP/decoding failures; API-level refusals surface as a normal
// response with StopReason "refusal" and are handled by the agent loop.
func (c *client) call(ctx context.Context, req messagesRequest) (*messagesResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, messagesURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", c.key)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("could not reach the Claude API: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return nil, fmt.Errorf("read Claude API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp.StatusCode, raw)
	}

	var out messagesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode Claude API response: %w", err)
	}
	if out.Type == "error" || out.Error != nil {
		msg := "the Claude API returned an error"
		if out.Error != nil && out.Error.Message != "" {
			msg = out.Error.Message
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return &out, nil
}

// httpStatusError maps a non-200 response to an actionable, secret-free message.
func httpStatusError(status int, raw []byte) error {
	// The API error body is small and safe to surface (it never echoes the key).
	detail := ""
	var e struct {
		Error *apiError `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != nil {
		detail = strings.TrimSpace(e.Error.Message)
	}
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("Claude rejected the API key (401) — check the key in Settings → AI Assistant")
	case http.StatusForbidden:
		return fmt.Errorf("the API key is not permitted to use this model (403)%s", suffix(detail))
	case http.StatusNotFound:
		return fmt.Errorf("model not found (404) — check the model name in Settings → AI Assistant%s", suffix(detail))
	case http.StatusTooManyRequests:
		return fmt.Errorf("Claude API rate limit reached (429) — wait a moment and try again")
	case http.StatusBadRequest:
		return fmt.Errorf("the Claude API rejected the request (400)%s", suffix(detail))
	default:
		if status >= 500 {
			return fmt.Errorf("the Claude API is temporarily unavailable (%d) — try again shortly", status)
		}
		return fmt.Errorf("the Claude API returned HTTP %d%s", status, suffix(detail))
	}
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}
