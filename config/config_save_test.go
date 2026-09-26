package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestSaveAtomicAndConcurrent verifies that Save writes valid JSON, leaves no
// leftover temp files, and never corrupts the file under concurrent writers.
func TestSaveAtomicAndConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()

	// Hammer Save from many goroutines at once. The save mutex + atomic
	// rename must guarantee the file is always complete, parseable JSON.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := *cfg
			c.CacheSize = n
			if err := Save(path, &c); err != nil {
				t.Errorf("Save failed: %v", err)
			}
		}(i)
	}
	wg.Wait()

	// File must exist and be valid JSON (never half-written).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("config.json is not valid JSON after concurrent saves: %v", err)
	}

	// No leftover .config-*.tmp files should remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir failed: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}
