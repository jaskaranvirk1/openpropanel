package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openpropanel/openpropanel/internal/config"
	"github.com/openpropanel/openpropanel/internal/domains"
	"github.com/openpropanel/openpropanel/internal/store"
)

const (
	maxTokens     = 4096
	maxIterations = 16 // tool-use rounds per user message
	maxMessages   = 80 // transcript turns retained per conversation
	maxConvs      = 64 // conversations kept in memory (LRU by last use)
	maxUserChars  = 8000
)

// ErrNotConfigured is returned when the operator has not finished configuring
// the AI assistant (provider/model/key) in Settings.
var ErrNotConfigured = errors.New("the AI assistant is not configured yet")

// Agent is the AI deployment assistant. It holds per-conversation transcripts in
// memory and, on each user message, runs a Claude tool-use loop that drives the
// panel's deployment operations.
type Agent struct {
	cfg   *config.Config
	dom   *domains.Service
	store *store.Store

	mu    sync.Mutex
	convs map[string]*conversation
}

// New builds the agent from the services the web server already holds.
func New(cfg *config.Config, dom *domains.Service, st *store.Store) *Agent {
	return &Agent{cfg: cfg, dom: dom, store: st, convs: map[string]*conversation{}}
}

type conversation struct {
	mu       sync.Mutex
	messages []wireMessage
	// mentioned accumulates ONLY operator-supplied text (their typed messages and
	// any domain this chat is scoped to) — never tool-result content. operatorNamed
	// checks a mutating action's target against it, so prompt-injected repository
	// text cannot pivot the agent onto a domain the operator never named.
	mentioned string
	lastUsed  time.Time
}

// maxMentioned bounds the operator-named allowlist text.
const maxMentioned = 16384

func boundedAppend(s, add string) string {
	s += add
	if len(s) > maxMentioned {
		s = s[len(s)-maxMentioned:]
	}
	return s
}

// Action is a mutating operation the agent performed on the server, surfaced to
// the chat UI so the operator sees exactly what changed.
type Action struct {
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
	Error   bool   `json:"error"`
}

// Reply is one assistant response: prose plus the list of actions taken.
type Reply struct {
	Text    string   `json:"text"`
	Actions []Action `json:"actions"`
}

// Configured reports whether the assistant is ready to use (Claude provider with
// a model and an API key on file).
func (a *Agent) Configured() bool {
	provider, model, key := a.cfg.AICredentials()
	return provider == "claude" && key != "" && strings.TrimSpace(model) != ""
}

// Chat processes one user message on conversation convID acting as actor, runs
// the tool-use loop (executing deployment actions as needed), and returns the
// assistant's reply. contextDomain (may be "") is the domain a per-domain chat
// is scoped to — the CALLER must have already authorized the actor for it; it is
// treated as operator-named and seeds the conversation's subject. It serializes
// concurrent posts to the same conversation.
func (a *Agent) Chat(ctx context.Context, actor *store.User, convID, userText, contextDomain string) (Reply, error) {
	if !a.Configured() {
		return Reply{}, ErrNotConfigured
	}
	userText = strings.TrimSpace(userText)
	if userText == "" {
		return Reply{}, errors.New("empty message")
	}
	if len(userText) > maxUserChars {
		userText = userText[:maxUserChars]
	}

	conv := a.conversation(convID)
	conv.mu.Lock()
	defer conv.mu.Unlock()

	// Record what the operator named (their message + the chat's scoped domain) so
	// operatorNamed can gate mutating actions. This is fed ONLY from operator input.
	first := len(conv.messages) == 0
	conv.mentioned = boundedAppend(conv.mentioned, " "+userText+" "+contextDomain)
	seed := userText
	if first && strings.TrimSpace(contextDomain) != "" {
		seed = "(This conversation is about the domain " + contextDomain + ".)\n\n" + userText
	}

	// Snapshot the last known-good transcript so a FAILED turn is rolled back
	// completely. A mid-turn API failure (rate limit, timeout, network blip) can
	// otherwise leave the transcript ending on a user turn — or an assistant
	// tool_use without its tool_result — and the next message would then be an
	// invalid request the API rejects for the rest of the conversation. Any
	// server-side actions already performed by executed tools persist; only the
	// corrupted transcript tail is discarded.
	snapshot := append([]wireMessage(nil), conv.messages...)

	userBlocks, _ := json.Marshal([]textBlock{{Type: "text", Text: seed}})
	conv.messages = append(conv.messages, wireMessage{Role: "user", Content: userBlocks})

	reply, err := a.run(ctx, actor, conv)
	conv.lastUsed = time.Now()
	if err != nil {
		conv.messages = snapshot
		return Reply{}, err
	}
	return reply, nil
}

// run drives the tool-use loop against the current transcript.
func (a *Agent) run(ctx context.Context, actor *store.User, conv *conversation) (Reply, error) {
	_, model, key := a.cfg.AICredentials()
	if strings.TrimSpace(model) == "" {
		model = DefaultModel
	}
	cl := newClient(key)
	specs := toolSpecs()

	var texts []string
	var actions []Action

	for i := 0; i < maxIterations; i++ {
		resp, err := cl.call(ctx, messagesRequest{
			Model:     model,
			MaxTokens: maxTokens,
			System:    systemPrompt,
			Messages:  conv.messages,
			Tools:     specs,
		})
		if err != nil {
			return Reply{}, err
		}

		// Preserve the assistant turn verbatim (tool_use blocks included) so it
		// can be replayed to the API on the next round exactly as required.
		conv.messages = append(conv.messages, wireMessage{Role: "assistant", Content: resp.Content})
		conv.messages = trimHistory(conv.messages)

		var blocks []contentBlock
		_ = json.Unmarshal(resp.Content, &blocks)

		var turnText []string
		var toolUses []contentBlock
		for _, b := range blocks {
			switch b.Type {
			case "text":
				if t := strings.TrimSpace(b.Text); t != "" {
					turnText = append(turnText, t)
				}
			case "tool_use":
				toolUses = append(toolUses, b)
			}
		}
		texts = append(texts, turnText...)

		// Terminal turn: a normal answer, a refusal, or (defensively) a tool_use
		// stop we couldn't parse. Replace the stored assistant turn with a clean,
		// non-empty, text-only turn. This guarantees the transcript always ends
		// with a valid assistant message and never a dangling tool_use — otherwise
		// the NEXT user message would form an invalid request (an unanswered
		// tool_use) that the API rejects for the rest of the conversation.
		if resp.StopReason != "tool_use" || len(toolUses) == 0 {
			final := strings.Join(turnText, "\n\n")
			if resp.StopReason == "refusal" {
				final = "I can't help with that request."
				texts = append(texts, final)
			}
			if strings.TrimSpace(final) == "" {
				final = "Done."
			}
			conv.messages[len(conv.messages)-1] = assistantTextMsg(final)
			return Reply{Text: strings.Join(texts, "\n\n"), Actions: actions}, nil
		}

		// Execute each requested tool and gather results into one user turn (all
		// tool_results for this assistant turn go back together, in order).
		results := make([]toolResultBlock, 0, len(toolUses))
		for _, tu := range toolUses {
			content, isErr, summary := a.dispatch(ctx, actor, conv.mentioned, tu.Name, tu.Input)
			results = append(results, toolResultBlock{
				Type:      "tool_result",
				ToolUseID: tu.ID,
				Content:   content,
				IsError:   isErr,
			})
			if summary != "" {
				actions = append(actions, Action{Tool: tu.Name, Summary: summary, Error: isErr})
			}
		}
		resultJSON, _ := json.Marshal(results)
		conv.messages = append(conv.messages, wireMessage{Role: "user", Content: resultJSON})
		conv.messages = trimHistory(conv.messages)
	}

	// Ran out of tool-use iterations: the transcript currently ends with a
	// tool_result user turn. Close with an assistant turn so the next user
	// message alternates correctly and the conversation stays usable.
	closing := "I've taken several steps but stopped to avoid running too long. Ask me to continue, or to check the deploy status."
	texts = append(texts, closing)
	conv.messages = append(conv.messages, assistantTextMsg(closing))
	return Reply{Text: strings.Join(texts, "\n\n"), Actions: actions}, nil
}

// assistantTextMsg builds a plain text-only assistant turn for the transcript.
func assistantTextMsg(text string) wireMessage {
	b, _ := json.Marshal([]textBlock{{Type: "text", Text: text}})
	return wireMessage{Role: "assistant", Content: b}
}

// conversation returns (creating if needed) the transcript for convID, evicting
// the least-recently-used conversation when the cap is exceeded.
func (a *Agent) conversation(convID string) *conversation {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.convs[convID]; ok {
		return c
	}
	if len(a.convs) >= maxConvs {
		var oldestKey string
		var oldest time.Time
		for k, c := range a.convs {
			if oldestKey == "" || c.lastUsed.Before(oldest) {
				oldestKey, oldest = k, c.lastUsed
			}
		}
		delete(a.convs, oldestKey)
	}
	c := &conversation{lastUsed: time.Now()}
	a.convs[convID] = c
	return c
}

// trimHistory bounds a transcript's length, cutting only at a "clean" user turn
// (a plain-text user message, never a tool_result) so a tool_use is never left
// without its matching tool_result and the first message stays a valid user turn.
func trimHistory(msgs []wireMessage) []wireMessage {
	if len(msgs) <= maxMessages {
		return msgs
	}
	// Find the earliest clean boundary that brings us within the cap.
	for i := len(msgs) - maxMessages; i < len(msgs); i++ {
		if msgs[i].Role == "user" && !isToolResult(msgs[i].Content) {
			return msgs[i:]
		}
	}
	return msgs
}

// isToolResult reports whether a user turn's content is tool_result blocks
// (which must not begin a transcript).
func isToolResult(content json.RawMessage) bool {
	var blocks []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
		return false
	}
	return blocks[0].Type == "tool_result"
}

// toolErr formats a tool failure as a result string for the model.
func toolErr(format string, args ...any) (string, bool, string) {
	return fmt.Sprintf(format, args...), true, ""
}
