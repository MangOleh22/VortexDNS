package dns

import (
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"vortexdns/advanced"
	"vortexdns/blocker"
	"vortexdns/cache"
	"vortexdns/config"
	"vortexdns/forwarder"
)

// QueryLogEntry represents a recorded DNS query event
type QueryLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	ClientIP  string    `json:"client_ip"`
	Status    string    `json:"status"` // "Allowed", "Blocked", "Cached"
	ElapsedMs int64     `json:"elapsed_ms"`
	// Upstream records who produced the answer: an upstream address, "Cache",
	// "Blocked", "Recursive" or "Local".
	Upstream string `json:"upstream"`
	// Dnssec reflects the response AD flag: "Secure" when the resolver signalled
	// authenticated data, "Insecure" otherwise, "—" when not applicable.
	Dnssec string `json:"dnssec"`
}

// DNSServer coordinates high-performance DNS serving, caching, and filtering
type DNSServer struct {
	cfg         *config.Config
	blocker     *blocker.Blocker
	cache       *cache.DNSCache
	forwarder   *forwarder.SmartForwarder
	advanced    *advanced.AdvancedEngine
	rateLimiter *RateLimiter

	udpServer *dns.Server
	tcpServer *dns.Server

	// Statistics
	TotalQueries   int64 `json:"total_queries"`
	BlockedQueries int64 `json:"blocked_queries"`
	CachedQueries  int64 `json:"cached_queries"`

	// Rcode breakdown counters (granular response outcomes). NOERROR is
	// derived by subtraction in the stats handler, so only the error codes
	// are tracked here.
	NxdomainQueries int64 `json:"nxdomain_queries"`
	RefusedQueries  int64 `json:"refused_queries"`
	ServfailQueries int64 `json:"servfail_queries"`

	// Query Circular Ring Buffer for Live Dashboard Log
	queryLogs   []*QueryLogEntry
	logHead     int  // Points to the next write position
	logFull     bool // Whether the ring buffer has wrapped around
	queryLogsMu sync.RWMutex
	logLimit    int

	// SSE Pub/Sub: each connected dashboard client gets its own channel
	subsMu      sync.Mutex
	subscribers map[chan *QueryLogEntry]struct{}
}

// NewServer builds a new DNSServer with connected components
func NewServer(cfg *config.Config, b *blocker.Blocker, c *cache.DNSCache, f *forwarder.SmartForwarder) *DNSServer {
	adv := advanced.GetInstance(cfg)
	s := &DNSServer{
		cfg:         cfg,
		blocker:     b,
		cache:       c,
		forwarder:   f,
		advanced:    adv,
		rateLimiter: NewRateLimiter(cfg.RateLimitQPS),
		logLimit:    500, // Keep last 500 queries in circular buffer
		queryLogs:   make([]*QueryLogEntry, 500),
		subscribers: make(map[chan *QueryLogEntry]struct{}),
	}

	// Restore recent history from access.log before serving. Without this the
	// dashboard's query log starts empty after every restart even though the
	// queries were persisted.
	s.hydrateFromAccessLog()

	// Proactively register advanced DoH / DoT handlers
	adv.StartDoHAndDoT(s.ServeDNS)

	return s
}

// hydrateFromAccessLog seeds the ring buffer from persisted queries, oldest
// first so the buffer's newest-last ordering is preserved. Called from
// NewServer before any listener starts, so no locking is required.
func (s *DNSServer) hydrateFromAccessLog() {
	persisted := s.advanced.ReadAccessLog(s.logLimit)
	if len(persisted) == 0 {
		return
	}

	// ReadAccessLog returns newest first; walk backwards to replay in order.
	for i := len(persisted) - 1; i >= 0; i-- {
		e := persisted[i]
		s.queryLogs[s.logHead] = &QueryLogEntry{
			Timestamp: e.Timestamp,
			Domain:    e.Domain,
			Type:      e.Type,
			ClientIP:  e.ClientIP,
			Status:    e.Status,
			ElapsedMs: e.ElapsedMs,
			// Not persisted in access.log; reported as unknown rather than guessed.
			Upstream: "—",
			Dnssec:   "—",
		}
		s.logHead = (s.logHead + 1) % s.logLimit
		if s.logHead == 0 {
			s.logFull = true
		}
	}

	log.Printf("[Server] Restored %d queries from access log", len(persisted))
}

// Start launches the UDP and TCP DNS servers in separate goroutines
func (s *DNSServer) Start() error {
	s.udpServer = &dns.Server{
		Addr:    s.cfg.BindAddress,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.ServeDNS),
	}

	s.tcpServer = &dns.Server{
		Addr:    s.cfg.BindAddress,
		Net:     "tcp",
		Handler: dns.HandlerFunc(s.ServeDNS),
	}

	errChan := make(chan error, 2)

	go func() {
		log.Printf("[Server] Starting UDP DNS server on %s", s.cfg.BindAddress)
		if err := s.udpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP server error: %w", err)
		}
	}()

	go func() {
		log.Printf("[Server] Starting TCP DNS server on %s", s.cfg.BindAddress)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP server error: %w", err)
		}
	}()

	// Wait briefly to see if binding failed immediately
	select {
	case err := <-errChan:
		return err
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

// Shutdown stops the server listeners gracefully
func (s *DNSServer) Shutdown() {
	if s.udpServer != nil {
		_ = s.udpServer.Shutdown()
	}
	if s.tcpServer != nil {
		_ = s.tcpServer.Shutdown()
	}
	log.Println("[Server] DNS Server shut down successfully")
}

// ServeDNS is the core request processing pipeline (Panic Recovery + Adblock + Cache + Forwarder)
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// 1. Crash/Panic Recovery Middleware (harus pertama agar menangkap semua panic)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Recovery] Critical Panic recovered: %v\nStack trace:\n%s", r, debug.Stack())
			if req != nil {
				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeServerFailure)
				s.recordRcode(dns.RcodeServerFailure)
				_ = w.WriteMsg(m)
			}
		}
	}()

	if req == nil {
		return
	}

	startTime := time.Now()
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	// Rate Limiting check
	if !s.rateLimiter.Allow(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		s.recordRcode(dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	// Validasi Question kosong sebelum diproses lebih lanjut
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		s.recordRcode(dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	// Access Control List (ACL) check
	if !s.advanced.IsAllowedByACL(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		s.recordRcode(dns.RcodeRefused)
		_ = w.WriteMsg(m)
		s.logQuery(req.Question[0].Name, "ANY", clientIP, "Blocked-ACL", 0)
		return
	}

	q := req.Question[0]
	domain := q.Name
	qTypeStr := dns.TypeToString[q.Qtype]

	// 1. Drop Requests configuration check
	for _, dropDomain := range s.cfg.DropRequests {
		if strings.Contains(strings.ToLower(domain), strings.ToLower(dropDomain)) {
			// Silently ignore query without sending any response
			return
		}
	}

	// Increment total query count
	s.incrementTotal()
	atomic.AddInt64(&s.advanced.TotalQueries, 1)

	// 2. CHAOS Zone Handling
	if q.Qclass == dns.ClassCHAOS && s.cfg.ChaosEnabled {
		resp := s.advanced.HandleChaos(q)
		resp.SetReply(req)
		_ = w.WriteMsg(resp)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// 3. AS112 Zones Protection
	if s.advanced.IsAS112(domain) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		s.recordRcode(dns.RcodeNameError)
		_ = w.WriteMsg(m)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}

	// 4. Filter AAAA
	if q.Qtype == dns.TypeAAAA && s.cfg.FilterAaaa {
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}

	// 5. Auto-PTR records handling
	if q.Qtype == dns.TypePTR {
		if resp := s.advanced.HandleAutoPTR(q); resp != nil {
			resp.SetReply(req)
			_ = w.WriteMsg(resp)
			elapsed := time.Since(startTime).Microseconds()
			s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
			return
		}
	}

	// 6. Safe Browsing / Malware check
	if s.advanced.IsMalicious(domain) {
		s.incrementBlocked()
		atomic.AddInt64(&s.advanced.BlockedQueries, 1)
		resp := s.buildBlockedResponse(req, q)
		_ = w.WriteMsg(resp)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}

	// 7. Parental Control / Adult Content check
	if s.advanced.IsAdultContent(domain) {
		s.incrementBlocked()
		atomic.AddInt64(&s.advanced.BlockedQueries, 1)
		resp := s.buildBlockedResponse(req, q)
		_ = w.WriteMsg(resp)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}
	// Kubernetes DNS integration
	if k8sResp := s.advanced.ResolveKubernetes(domain, q.Qtype); k8sResp != nil {
		k8sResp.SetReply(req)
		_ = w.WriteMsg(k8sResp)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// 8. Custom Authoritative Zone lookup
	if authRecords := s.advanced.LookupAuthoritative(domain, q.Qtype); authRecords != nil {
		m := new(dns.Msg)
		m.SetReply(req)

		// If len(authRecords) == 0 but it's not nil, it means it's a NODATA response (or wildcard empty)
		if len(authRecords) > 0 {
			m.Answer = append(m.Answer, authRecords...)
		}

		_ = w.WriteMsg(m)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// 9. Hosts file integration check
	if hostsIP := s.advanced.LookupHosts(domain); hostsIP != "" && q.Qtype == dns.TypeA {
		m := new(dns.Msg)
		m.SetReply(req)
		hdr := dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(hostsIP)})
		_ = w.WriteMsg(m)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// 10. Geo-based DNS routing routing
	if geoRecords := s.advanced.ResolveGeoDNS(domain, clientIP, q.Qtype); len(geoRecords) > 0 {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, geoRecords...)
		_ = w.WriteMsg(m)
		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// 11. Group-based filtering check
	clientGroupBlocked := false
	for _, gp := range s.cfg.Groups {
		for _, cliCIDR := range gp.Clients {
			_, ipNet, err := net.ParseCIDR(cliCIDR)
			if (err == nil && ipNet.Contains(net.ParseIP(clientIP))) || cliCIDR == clientIP {
				// Applies group custom blocking policy (if adblocker matches client rules)
				if s.blocker.IsBlocked(domain) {
					clientGroupBlocked = true
				}
			}
		}
	}

	// 12. Standard Ad-blocker & Advanced Blockers check
	if s.blocker.IsBlocked(domain) || clientGroupBlocked || s.advanced.IsServiceBlocked(domain) || s.advanced.IsScheduleBlocked(domain) {
		s.incrementBlocked()
		atomic.AddInt64(&s.advanced.BlockedQueries, 1)

		resp := s.buildBlockedResponse(req, q)
		_ = w.WriteMsg(resp)

		elapsed := time.Since(startTime).Microseconds()
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}

	// 13. Cache lookup with prefetching hook
	resolveFn := func(r *dns.Msg) (*dns.Msg, error) {
		return s.forwarder.Forward(r)
	}

	if resp, hit := s.cache.Get(req, resolveFn); hit {
		s.incrementCached()
		if resp != nil {
			s.recordRcode(resp.Rcode)
		}
		_ = w.WriteMsg(resp)

		elapsed := time.Since(startTime).Microseconds()
		s.logQueryFull(domain, qTypeStr, clientIP, "Cached", elapsed, "Cache", dnssecLabel(resp))
		return
	}

	// 13.5 ECS (EDNS Client Subnet) Injection
	// If EDNS is present or we need to add it, we inject the client's /24 (IPv4) or /56 (IPv6) subnet
	opt := req.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(1232)
		req.Extra = append(req.Extra, opt)
	}

	// Request DNSSEC records, otherwise the upstream omits RRSIG and there is
	// nothing for the validator to check.
	if s.cfg.DnssecEnabled {
		opt.SetDo()
	}

	// Check if subnet is already present, if not, add it
	hasSubnet := false
	for _, s := range opt.Option {
		if s.Option() == dns.EDNS0SUBNET {
			hasSubnet = true
			break
		}
	}
	if !hasSubnet {
		ip := net.ParseIP(clientIP)
		// Skip ECS for private/loopback clients: public upstreams (e.g. 8.8.8.8)
		// REFUSE queries carrying a bogon client-subnet. Common when running
		// behind NAT/Docker where the client IP is the internal bridge address.
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			ip = nil
		}
		if ip != nil {
			edns0Subnet := new(dns.EDNS0_SUBNET)
			edns0Subnet.Code = dns.EDNS0SUBNET
			edns0Subnet.SourceScope = 0
			if ip.To4() != nil {
				edns0Subnet.Family = 1 // IPv4
				edns0Subnet.SourceNetmask = 24
				edns0Subnet.Address = ip.To4()
			} else {
				edns0Subnet.Family = 2 // IPv6
				edns0Subnet.SourceNetmask = 56
				edns0Subnet.Address = ip
			}
			opt.Option = append(opt.Option, edns0Subnet)
		}
	}

	// 14. Split-Horizon select and Upstream resolve
	var resp *dns.Msg
	var err error
	// source records which resolver answered, for the query log.
	source := ""

	// First check conditional forwarding
	upstreams := s.advanced.GetConditionalUpstreams(domain)
	if len(upstreams) == 0 {
		upstreams = s.advanced.GetSplitHorizonUpstreams(clientIP)
	}

	if s.cfg.RecursiveResolver && len(s.advanced.GetConditionalUpstreams(domain)) == 0 {
		resp, err = s.advanced.ResolveRecursively(req)
		source = "Recursive"
	} else {
		// Use local config upstreams
		fwd := forwarder.New(upstreams, s.cfg.FailoverUpstreams)
		resp, source, err = fwd.ForwardWithSource(req)
	}

	elapsed := time.Since(startTime).Microseconds()

	if err != nil {
		log.Printf("[Server] Upstream forwarding failed for %s (%s): %v", domain, qTypeStr, err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		s.recordRcode(dns.RcodeServerFailure)
		_ = w.WriteMsg(m)

		s.logQuery(domain, qTypeStr, clientIP, "Allowed", elapsed)
		return
	}

	// Tally the upstream's response code so NXDOMAIN / SERVFAIL from resolvers
	// show up in the dashboard breakdown, not just locally-generated codes.
	if resp != nil {
		s.recordRcode(resp.Rcode)
	}

	// 15. DNS Rebinding check on response
	if s.advanced.IsRebindingResponse(resp) {
		resp = s.buildBlockedResponse(req, q)
		_ = w.WriteMsg(resp)
		s.logQuery(domain, qTypeStr, clientIP, "Blocked", elapsed)
		return
	}

	// 16. DNSSEC validation of upstream signatures
	s.advanced.SignDNSSEC(resp)

	// Report write failures: a response that cannot be packed or sent looks
	// exactly like a timeout to the client, so it must not fail silently.
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[Server] Failed to write response for %s (%s): %v", domain, qTypeStr, err)
	}

	// Save to cache
	s.cache.Set(req, resp)

	s.logQueryFull(domain, qTypeStr, clientIP, "Allowed", elapsed, source, dnssecLabel(resp))
}

// dnssecLabel maps a response's authenticated-data flag to a UI label.
func dnssecLabel(msg *dns.Msg) string {
	if msg == nil {
		return "—"
	}
	if msg.AuthenticatedData {
		return "Secure"
	}
	return "Insecure"
}

// buildBlockedResponse generates the appropriate response based on the query type (A -> 0.0.0.0, AAAA -> ::, default -> SOA)
func (s *DNSServer) buildBlockedResponse(req *dns.Msg, q dns.Question) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	// Check blocking mode for better anti-adblock stealth
	if s.cfg.BlockingMode == "nxdomain" {
		msg.SetRcode(req, dns.RcodeNameError)
		return msg
	}

	switch q.Qtype {
	case dns.TypeA:
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("0.0.0.0")})
	case dns.TypeAAAA:
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		msg.Answer = append(msg.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("::")})
	default:
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		msg.Ns = append(msg.Ns, &dns.SOA{
			Hdr:     hdr,
			Ns:      q.Name,
			Mbox:    "hostmaster.",
			Serial:  1,
			Refresh: 86400,
			Retry:   7200,
			Expire:  3600000,
			Minttl:  172800,
		})
	}

	return msg
}

// Stats getters & setters (Safe for concurrent operations)
func (s *DNSServer) incrementTotal() {
	atomic.AddInt64(&s.TotalQueries, 1)
}

func (s *DNSServer) incrementBlocked() {
	atomic.AddInt64(&s.BlockedQueries, 1)
}

func (s *DNSServer) incrementCached() {
	atomic.AddInt64(&s.CachedQueries, 1)
}

// ResetStats zeroes all live query counters (total, blocked, cached and the
// rcode breakdown). Used by the dashboard "reset statistics" action. Atomic
// stores keep it safe to call while queries are being served.
func (s *DNSServer) ResetStats() {
	atomic.StoreInt64(&s.TotalQueries, 0)
	atomic.StoreInt64(&s.BlockedQueries, 0)
	atomic.StoreInt64(&s.CachedQueries, 0)
	atomic.StoreInt64(&s.NxdomainQueries, 0)
	atomic.StoreInt64(&s.RefusedQueries, 0)
	atomic.StoreInt64(&s.ServfailQueries, 0)
	s.advanced.ResetStats()
}

// recordRcode tallies a response outcome by its DNS response code. Called on
// every terminal path so the dashboard can show a granular NOERROR / NXDOMAIN
// / REFUSED / SERVFAIL breakdown instead of just allowed/blocked/cached.
func (s *DNSServer) recordRcode(rcode int) {
	switch rcode {
	case dns.RcodeNameError:
		atomic.AddInt64(&s.NxdomainQueries, 1)
	case dns.RcodeRefused:
		atomic.AddInt64(&s.RefusedQueries, 1)
	case dns.RcodeServerFailure:
		atomic.AddInt64(&s.ServfailQueries, 1)
	}
}

// logQuery adds a query event to our circular ring buffer and broadcasts
// it to all connected SSE subscribers.
func (s *DNSServer) logQuery(domain, qType, clientIP, status string, elapsedMicroseconds int64) {
	upstream := "Local"
	if strings.HasPrefix(status, "Blocked") {
		upstream = "Blocked"
	}
	s.logQueryFull(domain, qType, clientIP, status, elapsedMicroseconds, upstream, "—")
}

// logQueryFull records a query event including which resolver answered it and
// the DNSSEC status of the response.
func (s *DNSServer) logQueryFull(domain, qType, clientIP, status string, elapsedMicroseconds int64, upstream, dnssec string) {
	elapsedMs := elapsedMicroseconds / 1000

	if upstream == "" {
		upstream = "Local"
	}
	if dnssec == "" {
		dnssec = "—"
	}

	// 1. Log to Access Log file
	s.advanced.WriteAccessLog(domain, qType, clientIP, status, elapsedMs)

	// 2. DNStap Binary logging simulation
	var qTypeUint uint16 = dns.TypeA
	if qType == "AAAA" {
		qTypeUint = dns.TypeAAAA
	}
	s.advanced.LogDNStap(domain, qTypeUint, clientIP, elapsedMs)

	// 3. Record long-term stats
	s.advanced.RecordLongTermStat(domain, qType, clientIP, status)

	entry := &QueryLogEntry{
		Timestamp: time.Now(),
		Domain:    domain,
		Type:      qType,
		ClientIP:  clientIP,
		Status:    status,
		ElapsedMs: elapsedMs,
		Upstream:  upstream,
		Dnssec:    dnssec,
	}

	// Store in efficient O(1) circular ring buffer
	s.queryLogsMu.Lock()
	s.queryLogs[s.logHead] = entry
	s.logHead = (s.logHead + 1) % s.logLimit
	if s.logHead == 0 {
		s.logFull = true // Buffer has wrapped around at least once
	}
	s.queryLogsMu.Unlock()

	// Fan-out broadcast to ALL connected SSE dashboard subscribers
	s.subsMu.Lock()
	for ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
			// If a specific client's channel is full, drop for that client only
			// This NEVER blocks the query processing pipeline
		}
	}
	s.subsMu.Unlock()
}

// GetLogs returns a copy of current logged queries for UI loading (newest first)
func (s *DNSServer) GetLogs() []*QueryLogEntry {
	s.queryLogsMu.RLock()
	defer s.queryLogsMu.RUnlock()

	var result []*QueryLogEntry

	if !s.logFull {
		// Buffer hasn't wrapped yet, read from index 0 to logHead
		result = make([]*QueryLogEntry, s.logHead)
		copy(result, s.queryLogs[:s.logHead])
	} else {
		// Buffer is full/wrapped: read from logHead forward (oldest first), then wrap
		result = make([]*QueryLogEntry, s.logLimit)
		copy(result, s.queryLogs[s.logHead:])
		copy(result[s.logLimit-s.logHead:], s.queryLogs[:s.logHead])
	}

	// Reverse to return newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	// Filter out nil slots
	filtered := result[:0]
	for _, e := range result {
		if e != nil {
			filtered = append(filtered, e)
		}
	}

	return filtered
}

// Subscribe registers a new SSE client channel. Call Unsubscribe when client disconnects.
func (s *DNSServer) Subscribe() chan *QueryLogEntry {
	ch := make(chan *QueryLogEntry, 256)
	s.subsMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes and closes an SSE client channel.
func (s *DNSServer) Unsubscribe(ch chan *QueryLogEntry) {
	s.subsMu.Lock()
	delete(s.subscribers, ch)
	s.subsMu.Unlock()
	close(ch)
}

// SubscribeLogs returns a channel for legacy compatibility (single consumer)
func (s *DNSServer) SubscribeLogs() chan *QueryLogEntry {
	return s.Subscribe()
}

// Advanced returns the AdvancedEngine instance for the dashboard to interact with
func (s *DNSServer) Advanced() *advanced.AdvancedEngine {
	return s.advanced
}

// RateLimiter tracks and limits DNS queries per IP address using a sliding window.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string][]time.Time
	qps     int
}

func NewRateLimiter(qps int) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string][]time.Time),
		qps:     qps,
	}

	// Start clean up ticker to prevent memory leaks from inactive clients
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.mu.Lock()
			now := time.Now()
			cutoff := now.Add(-time.Second)
			for ip, times := range rl.clients {
				if len(times) == 0 || times[len(times)-1].Before(cutoff) {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()

	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	if rl.qps <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

	times, exists := rl.clients[ip]
	if !exists {
		// Protect against UDP IP-spoofing memory exhaustion (OOM DoS)
		if len(rl.clients) > 100000 {
			// Emergency clear to survive DDoS
			rl.clients = make(map[string][]time.Time)
		}
		rl.clients[ip] = []time.Time{now}
		return true
	}

	validIdx := 0
	for i, t := range times {
		if t.After(cutoff) {
			validIdx = i
			break
		}
	}
	if len(times) > 0 && times[len(times)-1].Before(cutoff) {
		rl.clients[ip] = []time.Time{now}
		return true
	}
	times = times[validIdx:]

	if len(times) >= rl.qps {
		rl.clients[ip] = times
		return false
	}

	rl.clients[ip] = append(times, now)
	return true
}
