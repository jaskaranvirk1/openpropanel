package ai

import (
	"encoding/json"
	"testing"
)

func userText(s string) wireMessage {
	b, _ := json.Marshal([]textBlock{{Type: "text", Text: s}})
	return wireMessage{Role: "user", Content: b}
}

func userToolResult(id string) wireMessage {
	b, _ := json.Marshal([]toolResultBlock{{Type: "tool_result", ToolUseID: id, Content: "ok"}})
	return wireMessage{Role: "user", Content: b}
}

func TestOperatorNamed(t *testing.T) {
	cases := []struct {
		mentioned, domain string
		want              bool
	}{
		{"deploy https://github.com/me/app to shop.example.com", "shop.example.com", true}, // exact
		{"set up example.com please", "api.example.com", true},                             // operator named the parent
		{"deploy example.com", "victim.com", false},                                        // unrelated domain
		{"", "example.com", false},                                                         // nothing named
		{"work on example.com", "example.com.evil.com", false},                             // suffix-prefix attack
		{"i host example.com", "othersite.com", false},                                     // shares only the TLD
		{"Deploy EXAMPLE.COM now", "example.com", true},                                     // case-insensitive
		{"the api at api.example.com", "api.example.com", true},                            // subdomain named directly
		{"example.com", "com", false},                                                      // bare TLD never matches
		// Bypass attempts the whole-token host match must reject:
		{"connect https://github.com/eve/victim.com to myshop.example", "victim.com", false}, // URL path segment
		{"connect github.com/eve/victim.com to myshop.example", "victim.com", false},         // schemeless repo path
		{"please deploy notevil.com now", "evil.com", false},                                 // left-boundary substring
		{"my email is admin@big.com", "big.com", false},                                      // email domain
		{"deploy shop.example.com/admin now", "shop.example.com", true},                      // host with a path still names the host
		{"(shop.example.com)", "shop.example.com", true},                                     // surrounding punctuation
		{"deploy shop.example.com.", "shop.example.com", true},                               // trailing FQDN dot
	}
	for _, c := range cases {
		if got := operatorNamed(c.mentioned, c.domain); got != c.want {
			t.Errorf("operatorNamed(%q, %q) = %v, want %v", c.mentioned, c.domain, got, c.want)
		}
	}
}

func TestIsToolResult(t *testing.T) {
	if isToolResult(userText("hi").Content) {
		t.Fatal("a user text turn must not be classified as a tool_result")
	}
	if !isToolResult(userToolResult("t1").Content) {
		t.Fatal("a tool_result turn must be classified as such")
	}
	if isToolResult(json.RawMessage(`[]`)) {
		t.Fatal("empty content is not a tool_result boundary")
	}
	if isToolResult(json.RawMessage(`not json`)) {
		t.Fatal("invalid content must not be treated as a tool_result")
	}
}

func TestTrimHistoryShortIsUnchanged(t *testing.T) {
	msgs := []wireMessage{userText("a"), assistantTextMsg("b")}
	got := trimHistory(msgs)
	if len(got) != len(msgs) {
		t.Fatalf("short history must be unchanged: got %d want %d", len(got), len(msgs))
	}
}

// TestTrimHistoryKeepsTranscriptValid builds a long transcript of tool-use
// rounds (user text -> assistant tool_use -> user tool_result -> assistant text)
// and asserts trimHistory only ever cuts at a clean user-text boundary: the
// result must start with a user turn that is NOT a tool_result, so no tool_use is
// left orphaned and the first message is always a valid conversation start.
func TestTrimHistoryKeepsTranscriptValid(t *testing.T) {
	var msgs []wireMessage
	for round := 0; round < 60; round++ {
		msgs = append(msgs,
			userText("please deploy"),                 // clean user boundary
			assistantTextMsg("calling a tool"),        // stands in for assistant(tool_use)
			userToolResult("tool-"+string(rune(round))), // tool_result user turn (NOT a boundary)
			assistantTextMsg("done with that step"),
		)
		msgs = trimHistory(msgs)
	}
	if len(msgs) > maxMessages {
		t.Fatalf("transcript not bounded: %d > %d", len(msgs), maxMessages)
	}
	if msgs[0].Role != "user" {
		t.Fatalf("trimmed transcript must start with a user turn, got %q", msgs[0].Role)
	}
	if isToolResult(msgs[0].Content) {
		t.Fatal("trimmed transcript must NOT start with a tool_result (would orphan a tool_use)")
	}
}
