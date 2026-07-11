package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHubSignature(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main"}`)
	const secret = "0123456789abcdef0123456789abcdef"

	if !verifyGitHubSignature(body, secret, sign(body, secret)) {
		t.Error("valid signature must verify")
	}
	if verifyGitHubSignature(body, secret, sign(body, "wrong-secret")) {
		t.Error("wrong secret must fail")
	}
	if verifyGitHubSignature(body, "", sign(body, "")) {
		t.Error("empty secret must always fail (webhook disabled)")
	}
	if verifyGitHubSignature([]byte("tampered"), secret, sign(body, secret)) {
		t.Error("tampered body must fail")
	}

	valid := sign(body, secret)
	for name, header := range map[string]string{
		"missing prefix": strings.TrimPrefix(valid, "sha256="),
		"sha1 prefix":    "sha1=" + strings.TrimPrefix(valid, "sha256="),
		"truncated hex":  valid[:20],
		"uppercase hex":  "sha256=" + strings.ToUpper(strings.TrimPrefix(valid, "sha256=")),
		"trailing junk":  valid + "ff",
		"empty":          "",
		"garbage":        "sha256=zzzz",
	} {
		if verifyGitHubSignature(body, secret, header) {
			t.Errorf("%s must fail verification", name)
		}
	}
}

// GitHub's default content type wraps the JSON as payload=<urlencoded>; the
// handler must still find the ref (while HMAC stays over the raw body).
func TestHookPayloadFormEncoded(t *testing.T) {
	raw := []byte(`payload=%7B%22ref%22%3A%22refs%2Fheads%2Fmain%22%7D`)
	if got := string(hookPayload(raw)); got != `{"ref":"refs/heads/main"}` {
		t.Errorf("hookPayload = %q", got)
	}
	plain := []byte(`{"ref":"refs/heads/main"}`)
	if got := string(hookPayload(plain)); got != string(plain) {
		t.Errorf("plain JSON body must pass through, got %q", got)
	}
}

func TestDeliveryCacheBoundedReplay(t *testing.T) {
	c := newDeliveryCache(3)
	for _, id := range []string{"a", "b", "c"} {
		if c.remember(id) {
			t.Errorf("first sight of %q reported as replay", id)
		}
	}
	if !c.remember("a") {
		t.Error("replayed id must be detected")
	}
	c.remember("d") // evicts "a" (oldest)
	if c.remember("a") {
		t.Error("evicted id should be forgotten (bounded cache)")
	}
	if !c.remember("d") {
		t.Error("recent id must still be remembered")
	}
}
