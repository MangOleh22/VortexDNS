package advanced

import (
	"os"
	"path/filepath"
	"testing"

	"vortexdns/config"
)

// TestAnonymizeIP checks the masking matches AdGuard's scheme: last two octets
// of IPv4, last ten bytes of IPv6, and non-addresses passed through untouched.
func TestAnonymizeIP(t *testing.T) {
	cases := map[string]string{
		"192.168.10.74":  "192.168.0.0",
		"8.8.8.8":        "8.8.0.0",
		"2001:db8::abcd": "2001:db8::",
		"not-an-ip":      "not-an-ip",
	}
	for in, want := range cases {
		if got := anonymizeIP(in); got != want {
			t.Errorf("anonymizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAccessLogRoundTrip writes entries then reads them back newest-first,
// covering the JSONL format the dashboard depends on.
func TestAccessLogRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ae := &AdvancedEngine{cfg: &config.Config{}}
	ae.openAccessLog(filepath.Join(dir, "access.log"))

	ae.WriteAccessLog("first.com", "A", "10.0.0.1", "Allowed", 5)
	ae.WriteAccessLog("second.com", "A", "10.0.0.2", "Blocked", 0)

	got := ae.ReadAccessLog(10)
	if len(got) != 2 {
		t.Fatalf("read %d entries, want 2", len(got))
	}
	if got[0].Domain != "second.com" || got[1].Domain != "first.com" {
		t.Errorf("wrong order: got %q then %q, want newest first", got[0].Domain, got[1].Domain)
	}
	if got[0].Status != "Blocked" {
		t.Errorf("status = %q, want Blocked", got[0].Status)
	}
}

// TestAccessLogRotation forces a rotation and asserts the .1 backup appears and
// the active file is reset.
func TestAccessLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ae := &AdvancedEngine{cfg: &config.Config{}}
	ae.openAccessLog(path)

	// Push the counter past the threshold so the next write triggers rotation.
	ae.accessMu.Lock()
	ae.accessBytes = accessLogMaxBytes
	ae.accessMu.Unlock()

	ae.WriteAccessLog("rotate.com", "A", "10.0.0.3", "Allowed", 1)

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated backup %s.1: %v", path, err)
	}
	// The write that tripped rotation lands in the fresh file, so history for
	// that domain is still readable.
	if got := ae.ReadAccessLog(10); len(got) != 1 || got[0].Domain != "rotate.com" {
		t.Errorf("post-rotation read = %+v, want single rotate.com entry", got)
	}
}
