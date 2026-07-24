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
