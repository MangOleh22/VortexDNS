package storage

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// DB wraps a sqlx.DB and provides VortexDNS storage operations.
type DB struct {
	db *sqlx.DB
	mu sync.Mutex // serializes writes (SQLite single-writer)
}

// QueryLogEntry mirrors the query_log table.
type QueryLogEntry struct {
	ID        int64   `db:"id"         json:"id"`
	Timestamp string  `db:"timestamp"  json:"timestamp"`
	ClientIP  string  `db:"client_ip"  json:"client_ip"`
	Domain    string  `db:"domain"     json:"domain"`
	QType     string  `db:"qtype"      json:"qtype"`
	Answer    string  `db:"answer"     json:"answer"`
	Rcode     string  `db:"rcode"      json:"rcode"`
	Blocked   bool    `db:"blocked"    json:"blocked"`
	LatencyMs float64 `db:"latency_ms" json:"latency_ms"`
	Upstream  string  `db:"upstream"   json:"upstream"`
}

// AuditEntry mirrors the audit_log table.
type AuditEntry struct {
	ID        int64  `db:"id"        json:"id"`
	Timestamp string `db:"timestamp" json:"time"`
	Event     string `db:"event"     json:"event"`
	Detail    string `db:"detail"    json:"detail"`
	IP        string `db:"ip"        json:"ip"`
	OK        bool   `db:"ok"        json:"ok"`
}

// StatsHourly mirrors the stats_hourly table.
type StatsHourly struct {
	ID            int64   `db:"id"              json:"id"`
	Hour          string  `db:"hour"            json:"hour"`
	TotalQueries  int64   `db:"total_queries"   json:"total_queries"`
	Blocked       int64   `db:"blocked"         json:"blocked"`
	AvgLatencyMs  float64 `db:"avg_latency_ms"  json:"avg_latency_ms"`
	UniqueClients int64   `db:"unique_clients"  json:"unique_clients"`
}

const schema = `
CREATE TABLE IF NOT EXISTS query_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT    NOT NULL,
    client_ip  TEXT    NOT NULL,
    domain     TEXT    NOT NULL,
    qtype      TEXT    NOT NULL,
    answer     TEXT    NOT NULL DEFAULT '',
    rcode      TEXT    NOT NULL,
    blocked    INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL    NOT NULL DEFAULT 0,
    upstream   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_qlog_ts     ON query_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_qlog_domain ON query_log(domain);
CREATE INDEX IF NOT EXISTS idx_qlog_client ON query_log(client_ip);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    event     TEXT    NOT NULL,
    detail    TEXT    NOT NULL DEFAULT '',
    ip        TEXT    NOT NULL DEFAULT '',
    ok        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS stats_hourly (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    hour           TEXT    NOT NULL UNIQUE,
    total_queries  INTEGER NOT NULL DEFAULT 0,
    blocked        INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms REAL    NOT NULL DEFAULT 0,
    unique_clients INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_stats_hour ON stats_hourly(hour);
`

// Open creates (or opens) the SQLite database at dbDir/vortex.db with WAL mode.
func Open(dbDir string) (*DB, error) {
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, err
	}
	path := filepath.Join(dbDir, "vortex.db")
	db, err := sqlx.Open("sqlite", path+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	// Single connection for writes; reads can open more via WAL.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("[Storage] SQLite database ready at %s (WAL mode)", path)
	return &DB{db: db}, nil
}

// Close closes the database.
func (s *DB) Close() error {
	return s.db.Close()
}

// ── Audit Log ───────────────────────────────────────────────────────────────

// InsertAudit writes an audit entry.
func (s *DB) InsertAudit(event, detail, ip string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO audit_log (timestamp, event, detail, ip, ok) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Format("2006-01-02 15:04:05"), event, detail, ip, boolToInt(ok),
	)
	if err != nil {
		log.Printf("[Storage] audit insert error: %v", err)
	}
}

// RecentAudits returns the newest `limit` audit entries.
func (s *DB) RecentAudits(limit int) []AuditEntry {
	if limit <= 0 {
		limit = 200
	}
	var rows []AuditEntry
	if err := s.db.Select(&rows, `SELECT id, timestamp, event, detail, ip, ok FROM audit_log ORDER BY id DESC LIMIT ?`, limit); err != nil {
		log.Printf("[Storage] audit select error: %v", err)
		return nil
	}
	return rows
}

// ── Query Log ───────────────────────────────────────────────────────────────

// InsertQuery writes a DNS query log entry.
func (s *DB) InsertQuery(e QueryLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO query_log (timestamp, client_ip, domain, qtype, answer, rcode, blocked, latency_ms, upstream)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.ClientIP, e.Domain, e.QType, e.Answer, e.Rcode,
		boolToInt(e.Blocked), e.LatencyMs, e.Upstream,
	)
	if err != nil {
		log.Printf("[Storage] query insert error: %v", err)
	}
}

// RecentQueries returns the newest `limit` query log entries.
func (s *DB) RecentQueries(limit int) []QueryLogEntry {
	if limit <= 0 {
		limit = 500
	}
	var rows []QueryLogEntry
	if err := s.db.Select(&rows, `SELECT id, timestamp, client_ip, domain, qtype, answer, rcode, blocked, latency_ms, upstream FROM query_log ORDER BY id DESC LIMIT ?`, limit); err != nil {
		log.Printf("[Storage] query select error: %v", err)
		return nil
	}
	return rows
}

// QueryLogCount returns total rows in query_log.
func (s *DB) QueryLogCount() int64 {
	var n int64
	s.db.Get(&n, `SELECT COUNT(*) FROM query_log`)
	return n
}

// PruneQueryLog deletes entries older than the given duration.
func (s *DB) PruneQueryLog(retention time.Duration) {
	cutoff := time.Now().Add(-retention).Format("2006-01-02 15:04:05")
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM query_log WHERE timestamp < ?`, cutoff)
	if err != nil {
		log.Printf("[Storage] query prune error: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[Storage] Pruned %d old query log entries", n)
	}
}

// ── Stats Hourly ────────────────────────────────────────────────────────────

// UpsertStatsHourly increments the stats for the current hour.
func (s *DB) UpsertStatsHourly(blocked bool, latencyMs float64, clientIP string) {
	hour := time.Now().Format("2006-01-02T15")
	blockedInt := boolToInt(blocked)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Upsert: try insert, on conflict update accumulators.
	_, err := s.db.Exec(`
		INSERT INTO stats_hourly (hour, total_queries, blocked, avg_latency_ms, unique_clients)
		VALUES (?, 1, ?, ?, 1)
		ON CONFLICT(hour) DO UPDATE SET
			total_queries  = total_queries + 1,
			blocked        = blocked + excluded.blocked,
			avg_latency_ms = (avg_latency_ms * total_queries + excluded.avg_latency_ms) / (total_queries + 1),
			unique_clients = (SELECT COUNT(DISTINCT client_ip) FROM query_log
			                  WHERE timestamp >= ? AND timestamp < ?)
	`, hour, blockedInt, latencyMs, hour+":00:00", hour+":59:59")
	if err != nil {
		log.Printf("[Storage] stats upsert error: %v", err)
	}
}

// StatsRange returns hourly stats between two times.
func (s *DB) StatsRange(from, to string) []StatsHourly {
	var rows []StatsHourly
	if err := s.db.Select(&rows, `SELECT * FROM stats_hourly WHERE hour >= ? AND hour <= ? ORDER BY hour`, from, to); err != nil {
		log.Printf("[Storage] stats range error: %v", err)
		return nil
	}
	return rows
}

// PruneStats deletes stats older than the given duration.
func (s *DB) PruneStats(retention time.Duration) {
	cutoff := time.Now().Add(-retention).Format("2006-01-02T15")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`DELETE FROM stats_hourly WHERE hour < ?`, cutoff)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Underlying returns the raw *sql.DB for advanced usage (e.g. migration).
func (s *DB) Underlying() *sql.DB {
	return s.db.DB
}
