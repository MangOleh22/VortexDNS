package dashboard

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"

	"vortexdns/advanced"
	"vortexdns/blocker"
	"vortexdns/cache"
	"vortexdns/config"
	"vortexdns/dns"
	"vortexdns/forwarder"
	"vortexdns/scanner"
)

//go:embed web/*
var webFiles embed.FS

// DashboardServer coordinates the HTTP API and dynamic UI delivery
type DashboardServer struct {
	cfg        *config.Config
	server     *dns.DNSServer
	blocker    *blocker.Blocker
	updater    *blocker.BlockerUpdater
	cache      *cache.DNSCache
	forwarder  *forwarder.SmartForwarder
	scannerMgr *scanner.ScanManager
	mux        *http.ServeMux

	// Sessions
	sessionTokens map[string]time.Time
	sessionMu     sync.Mutex

	// Server start time, used for real uptime reporting
	startTime time.Time

	// In-memory audit trail (newest first, capped)
	auditLog []AuditEntry
	auditMu  sync.Mutex
}

// AuditEntry records an administrative action on the dashboard
type AuditEntry struct {
	Time   string `json:"time"`
	Event  string `json:"event"` // login | logout | config | block
	Detail string `json:"detail"`
	IP     string `json:"ip"`
	OK     bool   `json:"ok"`
}

// recordAudit prepends an audit entry, keeping only the newest 200.
func (ds *DashboardServer) recordAudit(r *http.Request, event, detail string, ok bool) {
	ip := clientIPOf(r)
	ds.auditMu.Lock()
	defer ds.auditMu.Unlock()
	ds.auditLog = append([]AuditEntry{{
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Event:  event,
		Detail: detail,
		IP:     ip,
		OK:     ok,
	}}, ds.auditLog...)
	if len(ds.auditLog) > 200 {
		ds.auditLog = ds.auditLog[:200]
	}
}

// clientIPOf extracts the caller IP, honouring X-Forwarded-For when present.
func clientIPOf(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// New creates a new DashboardServer instance
func New(cfg *config.Config, s *dns.DNSServer, b *blocker.Blocker, u *blocker.BlockerUpdater, c *cache.DNSCache, f *forwarder.SmartForwarder) *DashboardServer {
	ds := &DashboardServer{
		cfg:           cfg,
		server:        s,
		blocker:       b,
		updater:       u,
		cache:         c,
		forwarder:     f,
		scannerMgr:    scanner.NewManager(cfg.DatabaseDir, 2),
		mux:           http.NewServeMux(),
		sessionTokens: make(map[string]time.Time),
		startTime:     time.Now(),
	}

	ds.registerRoutes()
	return ds
}

// Start runs HTTP+HTTPS on the same port with auto-detection
func (ds *DashboardServer) Start() {
	adv := advanced.GetInstance(ds.cfg)
	tlsConfig, err := adv.GetTLSConfig()

	if err == nil && tlsConfig != nil {
		log.Printf("[Dashboard] Starting dual HTTP/HTTPS dashboard on %s (same port)", ds.cfg.DashboardAddress)

		// HTTP handler that redirects to HTTPS on the same port
		httpRedirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})

		httpsServer := &http.Server{
			Handler:   ds.mux,
			TLSConfig: tlsConfig,
		}

		go func() {
			ln, err := net.Listen("tcp", ds.cfg.DashboardAddress)
			if err != nil {
				log.Printf("[Dashboard] Failed to listen: %v", err)
				return
			}

			for {
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				go ds.handleDualConn(conn, tlsConfig, httpsServer, httpRedirect)
			}
		}()
	} else {
		log.Printf("[Dashboard] Starting HTTP dashboard on http://%s", ds.cfg.DashboardAddress)
		go func() {
			if err := http.ListenAndServe(ds.cfg.DashboardAddress, ds.mux); err != nil {
				log.Printf("[Dashboard] Server failed: %v", err)
			}
		}()
	}
}

// handleDualConn peeks the first byte to detect TLS (0x16) vs plaintext HTTP
func (ds *DashboardServer) handleDualConn(conn net.Conn, tlsConfig *tls.Config, httpsServer *http.Server, httpHandler http.Handler) {
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return
	}

	peeked := &prefixConn{Conn: conn, prefix: buf}

	if buf[0] == 0x16 { // TLS ClientHello starts with 0x16
		tlsConn := tls.Server(peeked, tlsConfig)
		httpsServer.ConnState = nil
		http.Serve(&singleConnListener{conn: tlsConn}, ds.mux)
	} else {
		// Plain HTTP, redirect to HTTPS
		http.Serve(&singleConnListener{conn: peeked}, httpHandler)
	}
}

// prefixConn prepends already-read bytes back to the connection
type prefixConn struct {
	net.Conn
	prefix []byte
	done   bool
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if !c.done && len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.done = true
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// singleConnListener wraps a single connection as a net.Listener
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// registerRoutes wires the REST and stream API handlers
func (ds *DashboardServer) registerRoutes() {
	// API routes (Protected)
	api := func(h http.HandlerFunc) http.HandlerFunc { return ds.authMiddleware(h) }
	ds.mux.HandleFunc("/api/stats", api(ds.handleStats))
	ds.mux.HandleFunc("/api/logs", api(ds.handleLogs))
	ds.mux.HandleFunc("/api/logs/access", api(ds.handleLogsAccess))
	ds.mux.HandleFunc("/api/logs/stream", api(ds.handleLogsStream))
	ds.mux.HandleFunc("/api/rules", api(ds.handleRules))
	ds.mux.HandleFunc("/api/rules/add", api(ds.handleRulesAdd))
	ds.mux.HandleFunc("/api/rules/remove", api(ds.handleRulesRemove))
	ds.mux.HandleFunc("/api/updater/status", api(ds.handleUpdaterStatus))
	ds.mux.HandleFunc("/api/updater/trigger", api(ds.handleUpdaterTrigger))
	ds.mux.HandleFunc("/api/cache/flush", api(ds.handleCacheFlush))
	ds.mux.HandleFunc("/api/stats/reset", api(ds.handleStatsReset))
	ds.mux.HandleFunc("/api/server/restart", api(ds.handleServerRestart))
	ds.mux.HandleFunc("/api/service/restart", api(ds.handleServerRestart))
	ds.mux.HandleFunc("/api/stats/detailed", api(ds.handleStatsDetailed))

	// Real-data APIs backing the dashboard UI (replaces former client-side dummies)
	ds.mux.HandleFunc("/api/clients", api(ds.handleClients))
	ds.mux.HandleFunc("/api/upstream", api(ds.handleUpstream))
	ds.mux.HandleFunc("/api/blocklists", api(ds.handleBlocklists))
	ds.mux.HandleFunc("/api/blocklists/update-all", api(ds.handleUpdaterTrigger))
	ds.mux.HandleFunc("/api/topdomains", api(ds.handleTopDomains))
	ds.mux.HandleFunc("/api/services", api(ds.handleServices))
	ds.mux.HandleFunc("/api/schedule", api(ds.handleSchedule))
	ds.mux.HandleFunc("/api/zones/records", api(ds.handleZoneRecords))
	ds.mux.HandleFunc("/api/audit", api(ds.handleAudit))
	ds.mux.HandleFunc("/api/syslog", api(ds.handleSyslog))
	ds.mux.HandleFunc("/api/dns/test", api(ds.handleDNSTest))
	ds.mux.HandleFunc("/api/status", api(ds.handleStatus))
	ds.mux.HandleFunc("/api/conditional", api(ds.handleConditional))

	// Advanced Features APIs
	ds.mux.HandleFunc("/api/advanced/config", api(ds.handleAdvancedConfig))
	ds.mux.HandleFunc("/api/advanced/whois", api(ds.handleAdvancedWhois))
	ds.mux.HandleFunc("/api/advanced/rdns", api(ds.handleAdvancedRDNS))
	ds.mux.HandleFunc("/api/advanced/logs/export", api(ds.handleAdvancedLogsExport))
	ds.mux.HandleFunc("/api/advanced/stats/longterm", api(ds.handleAdvancedStatsLongterm))

	// Web Intelligence & URL Scanner APIs (Objective 14)
	ds.mux.HandleFunc("/api/v1/scans", api(ds.handleScans))
	ds.mux.HandleFunc("/api/v1/scans/compare", api(ds.handleScansCompare))
	ds.mux.HandleFunc("/api/v1/scans/engine-status", api(ds.handleScansEngineStatus))
	ds.mux.HandleFunc("/api/v1/scans/", api(ds.handleScanDetail))

	// Public Prometheus metrics
	ds.mux.HandleFunc("/metrics", ds.handlePrometheusMetrics)

	// Auth routes (Public)
	ds.mux.HandleFunc("/api/auth/status", ds.handleAuthStatus)
	ds.mux.HandleFunc("/api/auth/setup", ds.handleAuthSetup)
	ds.mux.HandleFunc("/api/auth/login", ds.handleAuthLogin)
	ds.mux.HandleFunc("/api/auth/logout", ds.handleAuthLogout)

	// Sub-filesystem rooted at the "web" subdirectory inside the embedded FS.
	webSubFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatalf("[Dashboard] Failed to create web sub-filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(webSubFS))

	// Serve all static UI files
	ds.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Serve index.html for root path directly
		if r.URL.Path == "/" || r.URL.Path == "" {
			if !ds.isValidRequestSession(r) {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			f, err := webSubFS.Open("index.html")
			if err != nil {
				http.Error(w, "Dashboard tidak ditemukan", http.StatusNotFound)
				return
			}
			defer f.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, f)
			return
		}

		// Serve login.html for /login path
		if r.URL.Path == "/login" {
			if ds.isValidRequestSession(r) && ds.cfg.AdminPasswordHash != "" {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			f, err := webSubFS.Open("index.html")
			if err != nil {
				http.Error(w, "Login page not found", http.StatusNotFound)
				return
			}
			defer f.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, f)
			return
		}

		// Serve all other static assets (style.css, app.js, etc.)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	})
}

// Session Management
func (ds *DashboardServer) isValidRequestSession(r *http.Request) bool {
	cookie, err := r.Cookie("vortex_session")
	if err != nil {
		return false
	}

	ds.sessionMu.Lock()
	defer ds.sessionMu.Unlock()
	expiry, exists := ds.sessionTokens[cookie.Value]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(ds.sessionTokens, cookie.Value)
		return false
	}
	// Extend session
	ds.sessionTokens[cookie.Value] = time.Now().Add(24 * time.Hour)
	return true
}

func (ds *DashboardServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If setup is needed, allow nothing but auth APIs
		if ds.cfg.AdminPasswordHash == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "setup required"})
			return
		}

		if !ds.isValidRequestSession(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Auth Handlers
func (ds *DashboardServer) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	needsSetup := ds.cfg.AdminPasswordHash == ""
	isLoggedIn := ds.isValidRequestSession(r)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"needs_setup":  needsSetup,
		"is_logged_in": isLoggedIn,
	})
}

func (ds *DashboardServer) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	ds.sessionMu.Lock()
	defer ds.sessionMu.Unlock()

	if ds.cfg.AdminPasswordHash != "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "already setup"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username min 3, password min 6 chars"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to secure password"})
		return
	}

	ds.cfg.AdminUsername = req.Username
	ds.cfg.AdminPasswordHash = string(hash)
	config.Save("config.json", ds.cfg)

	ds.recordAudit(r, "config", "Setup admin awal — "+req.Username, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (ds *DashboardServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if ds.cfg.AdminPasswordHash == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "setup required"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	if req.Username != ds.cfg.AdminUsername {
		ds.recordAudit(r, "login", "Login gagal — username: "+req.Username, false)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(ds.cfg.AdminPasswordHash), []byte(req.Password)); err != nil {
		ds.recordAudit(r, "login", "Login gagal — username: "+req.Username, false)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Generate session token
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	ds.sessionMu.Lock()
	ds.sessionTokens[token] = time.Now().Add(24 * time.Hour)
	ds.sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "vortex_session",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	ds.recordAudit(r, "login", "Login berhasil — "+req.Username, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (ds *DashboardServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	cookie, err := r.Cookie("vortex_session")
	if err == nil {
		ds.sessionMu.Lock()
		delete(ds.sessionTokens, cookie.Value)
		ds.sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "vortex_session",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
	})

	ds.recordAudit(r, "logout", "Logout manual — "+ds.cfg.AdminUsername, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// JSON helpers
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func readJSON(r *http.Request, data interface{}) error {
	// Protect against large payload OOM attacks (max 5MB)
	r.Body = http.MaxBytesReader(nil, r.Body, 5*1024*1024)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(data)
}

// REST Handlers
func (ds *DashboardServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	exactRules, _, customWhitelist := ds.blocker.GetStats()
	_, totalUpdaterRules, lastUpdate, _ := ds.updater.GetStatus()
	adv := ds.server.Advanced()

	total := ds.server.TotalQueries
	blocked := ds.server.BlockedQueries
	cached := ds.server.CachedQueries

	// Rcode breakdown. NOERROR is derived: everything that wasn't an explicit
	// error code. Clamped at zero to stay sane if counters race slightly.
	nxdomain := ds.server.NxdomainQueries
	refused := ds.server.RefusedQueries
	servfail := ds.server.ServfailQueries
	noerror := total - nxdomain - refused - servfail
	if noerror < 0 {
		noerror = 0
	}

	blockPercent := 0.0
	if total > 0 {
		blockPercent = (float64(blocked) / float64(total)) * 100.0
	}

	// Derive latency and client metrics from the live query ring buffer.
	logs := ds.server.GetLogs()
	avgLatency, p95Latency := latencyStats(logs)
	activeClients := countActiveClients(logs, 5*time.Minute)

	dnssecTotal := adv.DnssecSignatures
	dnssecRate := "—"
	if total > 0 {
		dnssecRate = fmt.Sprintf("%.1f%%", (float64(dnssecTotal)/float64(total))*100.0)
	}

	stats := map[string]interface{}{
		"total_queries":     total,
		"blocked_queries":   blocked,
		"cached_queries":    cached,
		"noerror_queries":   noerror,
		"nxdomain_queries":  nxdomain,
		"refused_queries":   refused,
		"servfail_queries":  servfail,
		"block_percentage":  blockPercent,
		"total_rules":       exactRules + totalUpdaterRules,
		"whitelist_rules":   customWhitelist,
		"blocklist_count":   len(ds.cfg.BlocklistURLs),
		"cache_size":        ds.cache.GetStats(),
		"cache_min_ttl":     ds.cfg.CacheMinTTL,
		"upstreams":         ds.forwarder.GetStats(),
		"last_update":       lastUpdate.Format(time.RFC3339),
		"avg_latency":       avgLatency,
		"p95_latency":       p95Latency,
		"active_clients":    activeClients,
		"dnssec_rate":       dnssecRate,
		"dnssec_signatures": dnssecTotal,
		"malware_blocked":   adv.MalwareBlocked,
		"parental_blocked":  adv.ParentalBlocked,
		"rebinding_blocked": adv.RebindingBlocked,
		"uptime_seconds":    int64(time.Since(ds.startTime).Seconds()),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
	}

	writeJSON(w, http.StatusOK, stats)
}

// latencyStats returns the mean and 95th-percentile latency (ms) over logged queries.
func latencyStats(logs []*dns.QueryLogEntry) (avg int64, p95 int64) {
	if len(logs) == 0 {
		return 0, 0
	}
	values := make([]int64, 0, len(logs))
	var sum int64
	for _, e := range logs {
		values = append(values, e.ElapsedMs)
		sum += e.ElapsedMs
	}
	avg = sum / int64(len(values))

	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	idx := (len(values) * 95) / 100
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return avg, values[idx]
}

// countActiveClients counts distinct client IPs seen within the given window.
func countActiveClients(logs []*dns.QueryLogEntry, window time.Duration) int {
	cutoff := time.Now().Add(-window)
	seen := make(map[string]struct{})
	for _, e := range logs {
		if e.Timestamp.After(cutoff) {
			seen[e.ClientIP] = struct{}{}
		}
	}
	return len(seen)
}

func (ds *DashboardServer) handleStatsDetailed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	history := ds.server.Advanced().GetLongTermHistory()

	type clientStat struct {
		Total    int    `json:"total"`
		Blocked  int    `json:"blocked"`
		LastSeen string `json:"last_seen"`
	}

	clients := make(map[string]*clientStat)
	types := make(map[string]int)
	domains := make(map[string]int)

	for _, entry := range history {
		c, okC := entry["client"].(string)
		t, okT := entry["type"].(string)
		d, okD := entry["domain"].(string)
		status, okS := entry["status"].(string)
		// RecordLongTermStat stores the key "time" as a Unix timestamp.
		unixTime, okTime := entry["time"].(int64)

		if okC {
			if clients[c] == nil {
				clients[c] = &clientStat{}
			}
			clients[c].Total++
			if okS && strings.HasPrefix(status, "Blocked") {
				clients[c].Blocked++
			}
			if okTime {
				clients[c].LastSeen = time.Unix(unixTime, 0).Format(time.RFC3339)
			}
		}
		if okT {
			types[t]++
		}
		if okD {
			domains[d]++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"types":   types,
		"domains": domains,
	})
}

func (ds *DashboardServer) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	blacklist, whitelist := ds.blocker.GetRules()
	writeJSON(w, http.StatusOK, map[string][]string{
		"blacklist": blacklist,
		"whitelist": whitelist,
	})
}

type RuleRequest struct {
	Domain string `json:"domain"`
	Type   string `json:"type"` // "whitelist" or "blacklist"
}

func (ds *DashboardServer) handleRulesAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req RuleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty domain"})
		return
	}

	// Validate domain format: must contain a dot and no forbidden characters
	cleanDomain := strings.TrimPrefix(req.Domain, "*.")
	if !isValidDomain(cleanDomain) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid domain format"})
		return
	}

	if req.Type == "whitelist" {
		ds.blocker.AddWhitelist(req.Domain)
	} else if req.Type == "blacklist" {
		ds.blocker.AddBlacklist(req.Domain)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid type"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (ds *DashboardServer) handleRulesRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req RuleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty domain"})
		return
	}

	if req.Type == "whitelist" {
		ds.blocker.RemoveWhitelist(req.Domain)
	} else if req.Type == "blacklist" {
		ds.blocker.RemoveBlacklist(req.Domain)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid type"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (ds *DashboardServer) handleUpdaterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	isUpdating, totalRules, lastUpdate, errStr := ds.updater.GetStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"is_updating":  isUpdating,
		"total_rules":  totalRules,
		"last_update":  lastUpdate.Format(time.RFC3339),
		"update_error": errStr,
	})
}

func (ds *DashboardServer) handleUpdaterTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	ds.updater.StartUpdate()
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "update triggered"})
}

func (ds *DashboardServer) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ds.cache.Clear()
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// handleStatsReset zeroes all live query counters and clears long-term
// history. POST-only + auth-protected (registered behind authMiddleware).
func (ds *DashboardServer) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ds.server.ResetStats()
	ds.recordAudit(r, "config", "Statistik direset", true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (ds *DashboardServer) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})

	// Spawn a background routine to restart the service via systemd
	go func() {
		time.Sleep(1 * time.Second)
		exec.Command("systemctl", "restart", "vortexdns.service").Run()
	}()
}

// Advanced handlers for premium configurations and tools
func (ds *DashboardServer) handleAdvancedConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, ds.cfg)
		return
	} else if r.Method == http.MethodPost {
		var req config.Config
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload tidak valid"})
			return
		}

		// Never accept credentials through this endpoint; auth is managed by the
		// dedicated /api/auth routes.
		if len(req.UpstreamServers) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "minimal satu upstream harus diisi"})
			return
		}
		normalized := make([]string, 0, len(req.UpstreamServers))
		for _, u := range req.UpstreamServers {
			addr := normalizeUpstream(u, "")
			if addr == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream tidak valid: " + u})
				return
			}
			normalized = append(normalized, addr)
		}

		// Update core settings
		ds.cfg.UpstreamServers = normalized
		ds.cfg.ReverseDNSEnabled = req.ReverseDNSEnabled
		ds.cfg.WhoisEnabled = req.WhoisEnabled
		ds.cfg.SafeBrowsingEnabled = req.SafeBrowsingEnabled
		ds.cfg.ParentalControlEnabled = req.ParentalControlEnabled
		ds.cfg.DoHEnabled = req.DoHEnabled
		ds.cfg.DoHAddress = req.DoHAddress
		ds.cfg.DoTEnabled = req.DoTEnabled
		ds.cfg.DoTAddress = req.DoTAddress
		ds.cfg.DnssecEnabled = req.DnssecEnabled
		ds.cfg.TlsCertPath = req.TlsCertPath
		ds.cfg.TlsKeyPath = req.TlsKeyPath
		ds.cfg.RecursiveResolver = req.RecursiveResolver
		ds.cfg.Dns64Enabled = req.Dns64Enabled
		ds.cfg.DnstapEnabled = req.DnstapEnabled
		ds.cfg.As112Enabled = req.As112Enabled
		ds.cfg.ChaosEnabled = req.ChaosEnabled
		ds.cfg.PrometheusEnabled = req.PrometheusEnabled
		ds.cfg.PrometheusAddress = req.PrometheusAddress
		ds.cfg.SplitHorizon = req.SplitHorizon
		ds.cfg.KubernetesEnabled = req.KubernetesEnabled
		ds.cfg.HostsFileEnabled = req.HostsFileEnabled
		ds.cfg.FailoverUpstreams = req.FailoverUpstreams
		ds.cfg.ZoneRecords = req.ZoneRecords
		ds.cfg.BlockPageEnabled = req.BlockPageEnabled
		ds.cfg.DnsRebindingEnabled = req.DnsRebindingEnabled
		ds.cfg.DropRequests = req.DropRequests
		ds.cfg.FilterAaaa = req.FilterAaaa
		ds.cfg.GeoDns = req.GeoDns
		ds.cfg.NxDomainOverride = req.NxDomainOverride
		ds.cfg.AutoPtr = req.AutoPtr
		ds.cfg.GravityEnabled = req.GravityEnabled
		ds.cfg.GravityCronMinutes = req.GravityCronMinutes
		ds.cfg.Groups = req.Groups
		ds.cfg.LongTermStats = req.LongTermStats
		ds.cfg.StatsRetentionHours = req.StatsRetentionHours
		ds.cfg.DhcpEnabled = req.DhcpEnabled
		ds.cfg.DhcpRange = req.DhcpRange
		ds.cfg.DoQEnabled = req.DoQEnabled
		ds.cfg.DoQAddress = req.DoQAddress
		ds.cfg.RateLimitQPS = req.RateLimitQPS

		// Cache and access-control settings, previously not persisted from the UI
		if req.CacheSize > 0 {
			ds.cfg.CacheSize = req.CacheSize
		}
		if req.CacheMinTTL > 0 {
			ds.cfg.CacheMinTTL = req.CacheMinTTL
		}
		if req.CacheMaxTTL > 0 {
			ds.cfg.CacheMaxTTL = req.CacheMaxTTL
		}
		ds.cfg.CachePrefetch = req.CachePrefetch
		ds.cfg.AclAllow = req.AclAllow
		ds.cfg.AclDeny = req.AclDeny
		if req.BlockingMode == "nxdomain" || req.BlockingMode == "zero_ip" {
			ds.cfg.BlockingMode = req.BlockingMode
		}

		// New feature bindings
		ds.cfg.BlockedServices = req.BlockedServices
		ds.cfg.ScheduleRules = req.ScheduleRules
		ds.cfg.ConditionalForwarding = req.ConditionalForwarding
		ds.cfg.WildcardZones = req.WildcardZones

		err := config.Save("config.json", ds.cfg)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}

		// Apply what can take effect immediately. Listener changes (DoH/DoT/DoQ
		// addresses, bind address) still require a restart.
		ds.server.Advanced().SetConfig(ds.cfg)
		ds.applyUpstreams()

		ds.recordAudit(r, "config", "Update konfigurasi global", true)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":         "success",
			"message":        "konfigurasi berhasil disimpan",
			"restart_needed": true,
			"restart_reason": "perubahan listener (DoH/DoT/DoQ/bind address) berlaku setelah restart",
		})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (ds *DashboardServer) handleAdvancedWhois(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain kosong"})
		return
	}
	adv := ds.server.Advanced()
	res, err := adv.QueryWhois(domain)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": res})
}

func (ds *DashboardServer) handleAdvancedRDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip kosong"})
		return
	}
	adv := ds.server.Advanced()
	res, err := adv.ResolveRDNS(ip)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": res})
}

func (ds *DashboardServer) handleAdvancedLogsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=vortexdns_logs.json")
	writeJSON(w, http.StatusOK, ds.server.GetLogs())
}

func (ds *DashboardServer) handleAdvancedStatsLongterm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	adv := ds.server.Advanced()
	writeJSON(w, http.StatusOK, adv.GetLongTermHistory())
}

func (ds *DashboardServer) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if !ds.cfg.PrometheusEnabled {
		http.Error(w, "Prometheus metrics disabled", http.StatusNotFound)
		return
	}
	adv := ds.server.Advanced()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_queries_total Total DNS queries served by VortexDNS\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_queries_total counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_queries_total %d\n\n", adv.TotalQueries)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_queries_blocked Total DNS queries blocked\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_queries_blocked counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_queries_blocked %d\n\n", adv.BlockedQueries)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_dnssec_signatures Total DNSSEC signatures generated\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_dnssec_signatures counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_dnssec_signatures %d\n\n", adv.DnssecSignatures)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_as112_queries Total AS112 local zone queries matched\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_as112_queries counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_as112_queries %d\n\n", adv.As112Queries)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_malware_blocked Total malware queries blocked\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_malware_blocked counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_malware_blocked %d\n\n", adv.MalwareBlocked)

	_, _ = fmt.Fprintf(w, "# HELP vortexdns_parental_blocked Total parental content queries blocked\n")
	_, _ = fmt.Fprintf(w, "# TYPE vortexdns_parental_blocked counter\n")
	_, _ = fmt.Fprintf(w, "vortexdns_parental_blocked %d\n\n", adv.ParentalBlocked)

	_, _ = fmt.Fprint(w, scanner.PrometheusMetricsOutput())
}

// isValidDomain checks if a string is a plausible domain name.
// This is a pure format check: it deliberately performs no DNS resolution, so it
// never blocks the request path.
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 63 {
			return false
		}
		for _, c := range p {
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' && c != '_' {
				return false
			}
		}
		if p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
	}
	return true
}

// handleLogs serves the live query ring buffer (newest first), optionally limited.
func (ds *DashboardServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	logs := ds.server.GetLogs()
	if limit := parsePositiveInt(r.URL.Query().Get("limit"), 0); limit > 0 && limit < len(logs) {
		logs = logs[:limit]
	}
	writeJSON(w, http.StatusOK, logs)
}

func (ds *DashboardServer) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ch := ds.server.Subscribe()
	defer ds.server.Unsubscribe(ch)

	// Tell the client the stream is open before any query arrives, so the UI can
	// show a truthful "connected" state on an idle resolver.
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// Heartbeat keeps intermediaries from tearing down an idle SSE connection.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			bytes, err := json.Marshal(msg)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(bytes))
				flusher.Flush()
			}
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// parsePositiveInt parses a query parameter, returning fallback on any problem.
func parsePositiveInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return fallback
		}
	}
	if n == 0 {
		return fallback
	}
	return n
}

// ── Real-data handlers backing the dashboard UI ────────────────────────────

// handleClients aggregates per-client query counters from the live query log.
func (ds *DashboardServer) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	type clientRow struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Group    string `json:"group"`
		Queries  int    `json:"queries"`
		Blocked  int    `json:"blocked"`
		LastSeen string `json:"last_seen"`
	}

	adv := ds.server.Advanced()
	rows := make(map[string]*clientRow)
	latest := make(map[string]time.Time)

	for _, e := range ds.server.GetLogs() {
		row := rows[e.ClientIP]
		if row == nil {
			row = &clientRow{IP: e.ClientIP, Group: ds.groupOf(e.ClientIP)}
			rows[e.ClientIP] = row
		}
		row.Queries++
		if strings.HasPrefix(e.Status, "Blocked") {
			row.Blocked++
		}
		if e.Timestamp.After(latest[e.ClientIP]) {
			latest[e.ClientIP] = e.Timestamp
			row.LastSeen = e.Timestamp.Format(time.RFC3339)
		}
	}

	out := make([]*clientRow, 0, len(rows))
	for ip, row := range rows {
		// Resolve a friendly name only when reverse DNS is switched on, so we never
		// add latency to this endpoint against the operator's configuration.
		if ds.cfg.ReverseDNSEnabled {
			if name, err := adv.ResolveRDNS(ip); err == nil && name != "" {
				row.Hostname = strings.TrimSuffix(name, ".")
			}
		}
		if row.Hostname == "" {
			row.Hostname = ip
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Queries > out[j].Queries })

	writeJSON(w, http.StatusOK, out)
}

// groupOf returns the configured group name a client IP belongs to.
func (ds *DashboardServer) groupOf(ip string) string {
	parsed := net.ParseIP(ip)
	for _, g := range ds.cfg.Groups {
		for _, entry := range g.Clients {
			if entry == ip {
				return g.Name
			}
			if _, ipNet, err := net.ParseCIDR(entry); err == nil && parsed != nil && ipNet.Contains(parsed) {
				return g.Name
			}
		}
	}
	return "default"
}

// handleUpstream lists (GET), adds (POST) or removes (DELETE) upstream resolvers.
func (ds *DashboardServer) handleUpstream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		type upstreamRow struct {
			ID       string  `json:"id"`
			Server   string  `json:"server"`
			Proto    string  `json:"proto"`
			Latency  float64 `json:"latency"`
			Failures int     `json:"failures"`
			Status   string  `json:"status"`
			Failover bool    `json:"failover"`
		}

		failoverSet := make(map[string]bool, len(ds.cfg.FailoverUpstreams))
		for _, f := range ds.cfg.FailoverUpstreams {
			failoverSet[f] = true
		}

		stats := ds.forwarder.GetStats()
		rows := make([]upstreamRow, 0, len(stats))
		for _, s := range stats {
			status := "OK"
			switch {
			case s.Failures >= 3:
				status = "Down"
			case s.RTTMs >= 20:
				status = "Slow"
			}
			rows = append(rows, upstreamRow{
				ID:       s.Address,
				Server:   s.Address,
				Proto:    protoOf(s.Address),
				Latency:  roundTo1(s.RTTMs),
				Failures: s.Failures,
				Status:   status,
				Failover: failoverSet[s.Address],
			})
		}
		writeJSON(w, http.StatusOK, rows)

	case http.MethodPost:
		var req struct {
			Server   string `json:"server"`
			Protocol string `json:"protocol"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		addr := normalizeUpstream(req.Server, req.Protocol)
		if addr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "alamat upstream tidak valid"})
			return
		}
		for _, existing := range ds.cfg.UpstreamServers {
			if existing == addr {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "upstream sudah ada"})
				return
			}
		}
		ds.cfg.UpstreamServers = append(ds.cfg.UpstreamServers, addr)
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.applyUpstreams()
		ds.recordAudit(r, "config", "Tambah upstream: "+addr, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "server": addr})

	case http.MethodDelete:
		addr := r.URL.Query().Get("server")
		if addr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter server kosong"})
			return
		}
		remaining := make([]string, 0, len(ds.cfg.UpstreamServers))
		for _, existing := range ds.cfg.UpstreamServers {
			if existing != addr {
				remaining = append(remaining, existing)
			}
		}
		if len(remaining) == 0 {
			// Removing the last resolver would black-hole every query.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "minimal satu upstream harus tetap aktif"})
			return
		}
		ds.cfg.UpstreamServers = remaining
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.applyUpstreams()
		ds.recordAudit(r, "config", "Hapus upstream: "+addr, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// applyUpstreams rebuilds the live forwarder pool from the current config so
// upstream edits take effect without a restart.
func (ds *DashboardServer) applyUpstreams() {
	ds.forwarder.SetUpstreams(ds.cfg.UpstreamServers, ds.cfg.FailoverUpstreams)
}

// protoOf infers the transport from an upstream address.
func protoOf(addr string) string {
	switch {
	case strings.HasPrefix(addr, "https://"):
		return "DoH"
	case strings.HasPrefix(addr, "tls://"):
		return "DoT"
	case strings.HasPrefix(addr, "quic://"):
		return "DoQ"
	default:
		return "UDP"
	}
}

// normalizeUpstream validates an upstream and appends the default port when the
// caller supplied a bare IP for plain DNS.
func normalizeUpstream(server, protocol string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if strings.Contains(server, "://") {
		return server
	}
	switch strings.ToUpper(protocol) {
	case "DOH":
		return "https://" + server
	case "DOT":
		return "tls://" + server
	case "DOQ":
		return "quic://" + server
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		if net.ParseIP(server) == nil && !strings.Contains(server, ".") {
			return ""
		}
		return server + ":53"
	}
	return server
}

func roundTo1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

// handleBlocklists lists (GET), adds (POST) or removes (DELETE) blocklist sources.
func (ds *DashboardServer) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		type blocklistRow struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			URL     string `json:"url"`
			Fmt     string `json:"fmt"`
			Count   int    `json:"count"`
			Updated string `json:"updated"`
			Active  bool   `json:"active"`
		}

		_, totalRules, lastUpdate, _ := ds.updater.GetStatus()
		urls := ds.cfg.BlocklistURLs
		rows := make([]blocklistRow, 0, len(urls))

		// The updater merges every source into one rule set, so a per-list count is
		// not tracked. Report the shared total split evenly rather than inventing
		// per-list numbers the backend does not have.
		// ponytail: per-list rule counts need the updater to track counts per source;
		// add that when the UI needs exact attribution.
		share := 0
		if len(urls) > 0 {
			share = totalRules / len(urls)
		}
		updatedStr := "—"
		if !lastUpdate.IsZero() {
			updatedStr = lastUpdate.Format(time.RFC3339)
		}
		for _, u := range urls {
			rows = append(rows, blocklistRow{
				ID:      u,
				Name:    blocklistName(u),
				URL:     u,
				Fmt:     "Hosts/Domain",
				Count:   share,
				Updated: updatedStr,
				Active:  true,
			})
		}
		writeJSON(w, http.StatusOK, rows)

	case http.MethodPost:
		var req struct {
			URL string `json:"url"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		url := strings.TrimSpace(req.URL)
		if url == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "URL kosong"})
			return
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") &&
			!strings.HasPrefix(url, "file://") && !strings.HasPrefix(url, "/") {
			url = "https://" + url
		}
		for _, existing := range ds.cfg.BlocklistURLs {
			if existing == url {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "blocklist sudah ada"})
				return
			}
		}
		ds.cfg.BlocklistURLs = append(ds.cfg.BlocklistURLs, url)
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.updater.StartUpdate()
		ds.recordAudit(r, "config", "Tambah blocklist: "+url, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "url": url})

	case http.MethodDelete:
		url := r.URL.Query().Get("url")
		if url == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter url kosong"})
			return
		}
		remaining := make([]string, 0, len(ds.cfg.BlocklistURLs))
		for _, existing := range ds.cfg.BlocklistURLs {
			if existing != url {
				remaining = append(remaining, existing)
			}
		}
		ds.cfg.BlocklistURLs = remaining
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.updater.StartUpdate()
		ds.recordAudit(r, "config", "Hapus blocklist: "+url, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// blocklistName derives a readable label from a blocklist URL.
func blocklistName(url string) string {
	trimmed := strings.TrimSuffix(url, "/")
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	return trimmed
}

// handleTopDomains ranks domains from the live query log, split by outcome.
func (ds *DashboardServer) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := parsePositiveInt(r.URL.Query().Get("limit"), 10)
	blockedCount := make(map[string]int)
	allowedCount := make(map[string]int)
	cachedCount := make(map[string]int)
	typeCount := make(map[string]int)

	for _, e := range ds.server.GetLogs() {
		domain := strings.TrimSuffix(e.Domain, ".")
		switch {
		case strings.HasPrefix(e.Status, "Blocked"):
			blockedCount[domain]++
		case e.Status == "Cached":
			cachedCount[domain]++
			allowedCount[domain]++
		default:
			allowedCount[domain]++
		}
		if e.Type != "" {
			typeCount[e.Type]++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"blocked":  topN(blockedCount, limit),
		"allowed":  topN(allowedCount, limit),
		"cached":   topN(cachedCount, limit),
		"types":    typeCount,
		"protocol": ds.protocolBreakdown(),
	})
}

// protocolBreakdown reports which DNS transports are enabled, since per-transport
// query counters are not tracked in the hot path.
// ponytail: real per-protocol counters need atomic counters in the DoH/DoT/DoQ
// handlers; add them when the UI needs exact traffic share.
func (ds *DashboardServer) protocolBreakdown() map[string]bool {
	return map[string]bool{
		"UDP": true,
		"TCP": true,
		"DoH": ds.cfg.DoHEnabled,
		"DoT": ds.cfg.DoTEnabled,
		"DoQ": ds.cfg.DoQEnabled,
	}
}

type labelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// topN returns the highest-count entries of a counter map, descending.
func topN(counts map[string]int, n int) []labelCount {
	out := make([]labelCount, 0, len(counts))
	for label, count := range counts {
		out = append(out, labelCount{Label: label, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// handleServices lists the blockable service catalog (GET) or toggles one (POST).
func (ds *DashboardServer) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		blockedSet := make(map[string]bool, len(ds.cfg.BlockedServices))
		for _, s := range ds.cfg.BlockedServices {
			blockedSet[strings.ToLower(s)] = true
		}
		type serviceRow struct {
			ID      string `json:"id"`
			Blocked bool   `json:"blocked"`
		}
		catalog := advanced.GetServiceCatalog()
		rows := make([]serviceRow, 0, len(catalog))
		for _, id := range catalog {
			rows = append(rows, serviceRow{ID: id, Blocked: blockedSet[id]})
		}
		writeJSON(w, http.StatusOK, rows)

	case http.MethodPost:
		var req struct {
			ID      string `json:"id"`
			Blocked bool   `json:"blocked"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		id := strings.ToLower(strings.TrimSpace(req.ID))
		known := false
		for _, candidate := range advanced.GetServiceCatalog() {
			if candidate == id {
				known = true
				break
			}
		}
		if !known {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "service tidak dikenal"})
			return
		}

		remaining := make([]string, 0, len(ds.cfg.BlockedServices)+1)
		for _, s := range ds.cfg.BlockedServices {
			if strings.ToLower(s) != id {
				remaining = append(remaining, s)
			}
		}
		if req.Blocked {
			remaining = append(remaining, id)
		}
		ds.cfg.BlockedServices = remaining
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		action := "Izinkan service: "
		if req.Blocked {
			action = "Blokir service: "
		}
		ds.recordAudit(r, "block", action+id, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleSchedule reads (GET) or replaces (POST) the time-based filtering rules.
func (ds *DashboardServer) handleSchedule(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := ds.cfg.ScheduleRules
		if rules == nil {
			rules = []config.ScheduleRule{}
		}
		writeJSON(w, http.StatusOK, rules)

	case http.MethodPost:
		var req struct {
			Rules []config.ScheduleRule `json:"rules"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		for _, rule := range req.Rules {
			if !isValidClock(rule.StartTime) || !isValidClock(rule.EndTime) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format waktu harus HH:MM"})
				return
			}
		}
		ds.cfg.ScheduleRules = req.Rules
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.recordAudit(r, "config", fmt.Sprintf("Update jadwal filtering (%d aturan)", len(req.Rules)), true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// isValidClock checks an "HH:MM" 24-hour time string.
func isValidClock(s string) bool {
	t, err := time.Parse("15:04", s)
	_ = t
	return err == nil
}

// handleZoneRecords lists (GET), adds (POST) or removes (DELETE) local DNS records.
func (ds *DashboardServer) handleZoneRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		type zoneRow struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Value    string `json:"value"`
			TTL      uint32 `json:"ttl"`
			Wildcard bool   `json:"wildcard"`
		}
		rows := make([]zoneRow, 0, len(ds.cfg.ZoneRecords))
		for _, rec := range ds.cfg.ZoneRecords {
			rows = append(rows, zoneRow{
				ID:       rec.Name + "|" + rec.Type,
				Name:     rec.Name,
				Type:     rec.Type,
				Value:    rec.Value,
				TTL:      rec.TTL,
				Wildcard: strings.HasPrefix(rec.Name, "*."),
			})
		}
		writeJSON(w, http.StatusOK, rows)

	case http.MethodPost:
		var rec config.ZoneRecord
		if err := readJSON(r, &rec); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		rec.Name = strings.TrimSpace(strings.ToLower(rec.Name))
		rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
		rec.Value = strings.TrimSpace(rec.Value)
		if rec.Name == "" || rec.Value == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name dan value wajib diisi"})
			return
		}
		if _, ok := mdns.StringToType[rec.Type]; !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tipe record tidak dikenal"})
			return
		}
		if (rec.Type == "A" || rec.Type == "AAAA") && net.ParseIP(rec.Value) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value harus IP yang valid"})
			return
		}
		if rec.TTL == 0 {
			rec.TTL = 3600
		}

		ds.cfg.ZoneRecords = append(ds.cfg.ZoneRecords, rec)
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.recordAudit(r, "config", "Tambah zone record: "+rec.Name+" "+rec.Type, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	case http.MethodDelete:
		name := strings.ToLower(r.URL.Query().Get("name"))
		rType := strings.ToUpper(r.URL.Query().Get("type"))
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter name kosong"})
			return
		}
		remaining := make([]config.ZoneRecord, 0, len(ds.cfg.ZoneRecords))
		for _, rec := range ds.cfg.ZoneRecords {
			if strings.ToLower(rec.Name) == name && (rType == "" || strings.ToUpper(rec.Type) == rType) {
				continue
			}
			remaining = append(remaining, rec)
		}
		ds.cfg.ZoneRecords = remaining
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.recordAudit(r, "config", "Hapus zone record: "+name, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAudit returns the recorded administrative actions, newest first.
func (ds *DashboardServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ds.auditMu.Lock()
	entries := make([]AuditEntry, len(ds.auditLog))
	copy(entries, ds.auditLog)
	ds.auditMu.Unlock()
	writeJSON(w, http.StatusOK, entries)
}

// handleLogsAccess serves query history persisted to access.log. This is
// separate from /api/logs, which serves the in-memory ring buffer: the ring
// buffer holds only the newest 500 entries, while this reaches further back.
func (ds *DashboardServer) handleLogsAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := parsePositiveInt(r.URL.Query().Get("limit"), 500)
	entries := ds.server.Advanced().ReadAccessLog(limit)
	if entries == nil {
		entries = []advanced.AccessEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleSyslog tails the process log so the UI shows real server output.
//
// Only the process log is considered here. The access log is deliberately
// excluded: it is served by /api/logs and /api/logs/access, and mixing DNS
// queries into this panel would bury the startup and error lines that are the
// reason to open it.
func (ds *DashboardServer) handleSyslog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := parsePositiveInt(r.URL.Query().Get("limit"), 200)

	// Configured path first, then the installed location, then the working
	// directory for development runs. The relative path alone was never found
	// when running as a service from /var/lib/vortexdns.
	candidates := []string{}
	if ds.cfg.LogFilePath != "" {
		candidates = append(candidates, ds.cfg.LogFilePath)
	}
	candidates = append(candidates, "/var/log/vortexdns/vortex.log", "vortex.log")

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"source": path, "lines": lines})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"source": "",
		"lines":  []string{},
		"note":   "Log proses belum ada. File ini dibuat setelah instalasi; saat jalan dari terminal output hanya ke stdout.",
	})
}

// handleDNSTest resolves a domain through this server's own pipeline.
func (ds *DashboardServer) handleDNSTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain kosong"})
		return
	}
	if !isValidDomain(strings.TrimPrefix(domain, "*.")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format domain tidak valid"})
		return
	}

	qType := mdns.TypeA
	if t, ok := mdns.StringToType[strings.ToUpper(r.URL.Query().Get("type"))]; ok {
		qType = t
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(domain), qType)

	start := time.Now()
	resp, err := ds.forwarder.Forward(msg)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"domain":  domain,
			"error":   err.Error(),
			"latency": elapsed,
			"blocked": ds.blocker.IsBlocked(mdns.Fqdn(domain)),
		})
		return
	}

	answers := make([]map[string]interface{}, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		hdr := rr.Header()
		answers = append(answers, map[string]interface{}{
			"name":  hdr.Name,
			"type":  mdns.TypeToString[hdr.Rrtype],
			"ttl":   hdr.Ttl,
			"value": strings.TrimPrefix(rr.String(), hdr.String()),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain":  domain,
		"type":    mdns.TypeToString[qType],
		"rcode":   mdns.RcodeToString[resp.Rcode],
		"latency": elapsed,
		"answers": answers,
		"blocked": ds.blocker.IsBlocked(mdns.Fqdn(domain)),
	})
}

// handleStatus reports which listeners and features are actually enabled, so the
// UI status panel reflects configuration instead of assuming everything runs.
func (ds *DashboardServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	isUpdating, totalRules, lastUpdate, updateErr := ds.updater.GetStatus()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"dns": map[string]interface{}{
			"enabled": true,
			"address": ds.cfg.BindAddress,
		},
		"doh":           featureStatus(ds.cfg.DoHEnabled, ds.cfg.DoHAddress),
		"dot":           featureStatus(ds.cfg.DoTEnabled, ds.cfg.DoTAddress),
		"doq":           featureStatus(ds.cfg.DoQEnabled, ds.cfg.DoQAddress),
		"recursive":     featureStatus(ds.cfg.RecursiveResolver, ""),
		"dnssec":        featureStatus(ds.cfg.DnssecEnabled, ""),
		"rate_limit":    featureStatus(ds.cfg.RateLimitQPS > 0, fmt.Sprintf("%d qps", ds.cfg.RateLimitQPS)),
		"acl":           featureStatus(len(ds.cfg.AclAllow) > 0 || len(ds.cfg.AclDeny) > 0, ""),
		"prometheus":    featureStatus(ds.cfg.PrometheusEnabled, ds.cfg.PrometheusAddress),
		"dhcp":          featureStatus(ds.cfg.DhcpEnabled, ds.cfg.DhcpRange),
		"safe_browsing": featureStatus(ds.cfg.SafeBrowsingEnabled, ""),
		"parental":      featureStatus(ds.cfg.ParentalControlEnabled, ""),
		"geo_dns":       featureStatus(ds.cfg.GeoDns, ""),
		"blocklist_sync": map[string]interface{}{
			"updating":    isUpdating,
			"total_rules": totalRules,
			"last_update": lastUpdate.Format(time.RFC3339),
			"error":       updateErr,
		},
		"uptime_seconds": int64(time.Since(ds.startTime).Seconds()),
		"version":        "1.0.0",
	})
}

// featureStatus describes a toggleable feature for the status panel.
func featureStatus(enabled bool, detail string) map[string]interface{} {
	return map[string]interface{}{"enabled": enabled, "address": detail}
}

// handleConditional lists (GET), adds (POST) or removes (DELETE) conditional
// forwarding rules, which route a domain suffix to specific upstreams.
func (ds *DashboardServer) handleConditional(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := ds.cfg.ConditionalForwarding
		if rules == nil {
			rules = []config.ConditionalForwardRule{}
		}
		writeJSON(w, http.StatusOK, rules)

	case http.MethodPost:
		var rule config.ConditionalForwardRule
		if err := readJSON(r, &rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		rule.Domain = strings.ToLower(strings.TrimSpace(rule.Domain))
		if rule.Domain == "" || !isValidDomain(strings.TrimPrefix(rule.Domain, "*.")) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain tidak valid"})
			return
		}
		normalized := make([]string, 0, len(rule.Upstreams))
		for _, u := range rule.Upstreams {
			addr := normalizeUpstream(u, "")
			if addr == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "upstream tidak valid: " + u})
				return
			}
			normalized = append(normalized, addr)
		}
		if len(normalized) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "minimal satu upstream harus diisi"})
			return
		}
		rule.Upstreams = normalized

		// Replace an existing rule for the same domain instead of duplicating it.
		updated := make([]config.ConditionalForwardRule, 0, len(ds.cfg.ConditionalForwarding)+1)
		for _, existing := range ds.cfg.ConditionalForwarding {
			if strings.EqualFold(existing.Domain, rule.Domain) {
				continue
			}
			updated = append(updated, existing)
		}
		ds.cfg.ConditionalForwarding = append(updated, rule)
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.server.Advanced().SetConfig(ds.cfg)
		ds.recordAudit(r, "config", "Set conditional forwarding: "+rule.Domain, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	case http.MethodDelete:
		domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		if domain == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter domain kosong"})
			return
		}
		remaining := make([]config.ConditionalForwardRule, 0, len(ds.cfg.ConditionalForwarding))
		for _, existing := range ds.cfg.ConditionalForwarding {
			if strings.EqualFold(existing.Domain, domain) {
				continue
			}
			remaining = append(remaining, existing)
		}
		ds.cfg.ConditionalForwarding = remaining
		if err := config.Save("config.json", ds.cfg); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "gagal menyimpan konfigurasi"})
			return
		}
		ds.server.Advanced().SetConfig(ds.cfg)
		ds.recordAudit(r, "config", "Hapus conditional forwarding: "+domain, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// ── Web Intelligence & URL Scanner Handlers (Objective 14) ──────────────────

type scanCreateRequest struct {
	URL    string              `json:"url"`
	Config *scanner.ScanConfig `json:"config,omitempty"`
}

func (ds *DashboardServer) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req scanCreateRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
			return
		}
		req.URL = strings.TrimSpace(req.URL)
		if req.URL == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "URL cannot be empty"})
			return
		}

		scan, err := ds.scannerMgr.CreateScan(req.URL, req.Config)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		ds.recordAudit(r, "scan", fmt.Sprintf("Initiated website scan: %s (id: %s)", scan.TargetHost, scan.ID), true)
		writeJSON(w, http.StatusCreated, scan)

	case http.MethodGet:
		limit := parsePositiveInt(r.URL.Query().Get("limit"), 20)
		offset := parsePositiveInt(r.URL.Query().Get("offset"), 0)
		scans, total := ds.scannerMgr.ListScans(limit, offset)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"scans":  scans,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (ds *DashboardServer) handleScansCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	baseID := strings.TrimSpace(r.URL.Query().Get("base"))
	targetID := strings.TrimSpace(r.URL.Query().Get("target"))
	if baseID == "" || targetID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "both 'base' and 'target' query parameters are required"})
		return
	}

	diff, err := ds.scannerMgr.CompareScans(baseID, targetID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, diff)
}

func (ds *DashboardServer) handleScansEngineStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pdf":        scanner.CheckPDFEngine(),
		"lighthouse": scanner.IsLighthouseAvailable(),
	})
}

func (ds *DashboardServer) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	// Path format: /api/v1/scans/{scan_id} or /api/v1/scans/{scan_id}/...
	subPath := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(strings.Trim(subPath, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	scanID := parts[0]

	// Handle scan deletion or cancellation
	if r.Method == http.MethodDelete {
		ok := ds.scannerMgr.DeleteScan(scanID)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
			return
		}
		ds.recordAudit(r, "scan", "Deleted/cancelled scan: "+scanID, true)
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "scan_id": scanID})
		return
	}

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	scan, found := ds.scannerMgr.GetScan(scanID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	// Route based on subpath
	if len(parts) == 1 {
		// GET /api/v1/scans/{scan_id}
		writeJSON(w, http.StatusOK, scan)
		return
	}

	action := parts[1]
	switch action {
	case "events":
		// GET /api/v1/scans/{scan_id}/events
		ds.handleScanEvents(w, r, scanID)

	case "report":
		// GET /api/v1/scans/{scan_id}/report
		if scan.Report == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not ready yet"})
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(scanner.GenerateHTMLReport(scan.Report)))
			return
		}
		writeJSON(w, http.StatusOK, scan.Report)

	case "export":
		if len(parts) < 3 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing export format (json, jsonl, csv, pdf)"})
			return
		}
		if scan.Report == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not ready for export"})
			return
		}

		format := strings.ToLower(parts[2])
		scanner.IncExportRequests()

		switch format {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-report.json\"", scanID))
			_ = scanner.ExportJSON(w, scan.Report)

		case "jsonl":
			w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-report.jsonl\"", scanID))
			_ = scanner.ExportJSONL(w, scan.Report)

		case "csv":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-findings.csv\"", scanID))
			_ = scanner.ExportCSV(w, scan.Report)

		case "pdf":
			pdfPath := filepath.Join(ds.cfg.DatabaseDir, "reports", fmt.Sprintf("%s.pdf", scanID))
			if _, err := os.Stat(pdfPath); err == nil {
				w.Header().Set("Content-Type", "application/pdf")
				w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s-report.pdf\"", scanID))
				http.ServeFile(w, r, pdfPath)
				return
			}
			// Fallback: render standalone printable HTML
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s-report.html\"", scanID))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(scanner.GenerateHTMLReport(scan.Report)))

		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported export format: " + format})
		}

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "endpoint not found"})
	}
}

func (ds *DashboardServer) handleScanEvents(w http.ResponseWriter, r *http.Request, scanID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ch, history, unsubscribe := ds.scannerMgr.SubscribeEvents(scanID)
	defer unsubscribe()

	// Initial connect handshake
	fmt.Fprint(w, ": connected\n\n")

	// Stream buffered historical events to fast-forward state
	for _, ev := range history {
		data, err := json.Marshal(ev.Data)
		if err == nil {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Event, string(data))
		}
	}
	flusher.Flush()

	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev.Data)
			if err == nil {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Event, string(data))
				flusher.Flush()
			}
			if ev.Event == "scan.completed" || ev.Event == "scan.failed" || ev.Event == "scan.cancelled" {
				return
			}
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
