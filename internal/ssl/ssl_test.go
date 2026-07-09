package ssl

import "testing"

func TestAnyMatch(t *testing.T) {
	server := map[string]bool{"148.113.192.208": true, "2001:db8::1": true}
	cases := []struct {
		name     string
		resolved []string
		want     bool
	}{
		{"exact IPv4 match", []string{"148.113.192.208"}, true},
		{"parking IP mismatch", []string{"162.255.119.224"}, false},
		{"one of several matches", []string{"1.2.3.4", "148.113.192.208"}, true},
		{"IPv6 canonicalised match", []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, true},
		{"empty", nil, false},
		{"garbage ignored", []string{"not-an-ip"}, false},
	}
	for _, c := range cases {
		if got := anyMatch(c.resolved, server); got != c.want {
			t.Errorf("%s: anyMatch(%v)=%v, want %v", c.name, c.resolved, got, c.want)
		}
	}
}

func TestIPHintPrefersPublic(t *testing.T) {
	// A private + public IP present: the hint must surface the public one.
	got := ipHint(map[string]bool{"10.0.0.5": true, "148.113.192.208": true})
	if got != " (148.113.192.208)" {
		t.Errorf("ipHint = %q, want the public IP", got)
	}
	if ipHint(map[string]bool{}) != "" {
		t.Errorf("ipHint(empty) should be blank")
	}
}

func TestDroppedNote(t *testing.T) {
	if droppedNote(nil) != "" {
		t.Error("no dropped names should yield empty note")
	}
	got := droppedNote([]string{"www.example.com"})
	want := " Skipped (no DNS record): www.example.com."
	if got != want {
		t.Errorf("droppedNote = %q, want %q", got, want)
	}
}
