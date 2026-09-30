package blocker

import "testing"

func TestIsLocalPath(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/hosts":            false,
		"http://example.com/hosts":             false,
		"vortex_db/lists/82bbcf0.txt":          true,
		"/etc/vortexdns/lists/foo.txt":         true,
		"file:///abs/path.txt":                 true,
		"./relative.txt":                       true,
	}
	for src, want := range cases {
		if got := isLocalPath(src); got != want {
			t.Errorf("isLocalPath(%q) = %v, want %v", src, got, want)
		}
	}
}
