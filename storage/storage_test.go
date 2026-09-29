package storage

import (
	"os"
	"testing"
	"time"
)

func TestOpenAndCreateTables(t *testing.T) {
	dir, _ := os.MkdirTemp("", "vortex-db-test")
	defer os.RemoveAll(dir)

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	// Insert + read audit
	db.InsertAudit("login", "admin logged in", "127.0.0.1", true)
	db.InsertAudit("config", "changed upstream", "10.0.0.1", true)
	audits := db.RecentAudits(10)
	if len(audits) != 2 {
		t.Fatalf("expected 2 audits, got %d", len(audits))
	}
	if audits[0].Event != "config" { // newest first
		t.Fatalf("expected newest first, got %s", audits[0].Event)
	}

	// Insert + read query log
	db.InsertQuery(QueryLogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		ClientIP:  "192.168.1.10",
		Domain:    "google.com",
		QType:     "A",
		Answer:    "142.250.4.100",
		Rcode:     "NOERROR",
		Blocked:   false,
		LatencyMs: 12.5,
		Upstream:  "1.1.1.1:53",
	})
	queries := db.RecentQueries(10)
	if len(queries) != 1 {
		t.Fatalf("expected 1 query, got %d", len(queries))
	}
	if queries[0].Domain != "google.com" {
		t.Fatalf("expected google.com, got %s", queries[0].Domain)
	}

	// Count
	if n := db.QueryLogCount(); n != 1 {
		t.Fatalf("expected count 1, got %d", n)
	}

	// Stats upsert
	db.UpsertStatsHourly(false, 12.5, "192.168.1.10")
	db.UpsertStatsHourly(true, 0.1, "192.168.1.20")
	hour := time.Now().Format("2006-01-02T15")
	stats := db.StatsRange(hour, hour)
	if len(stats) != 1 {
		t.Fatalf("expected 1 stats row, got %d", len(stats))
	}
	if stats[0].TotalQueries != 2 {
		t.Fatalf("expected 2 total queries, got %d", stats[0].TotalQueries)
	}
}
