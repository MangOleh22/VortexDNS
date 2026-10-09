package advanced

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"vortexdns/config"
)

// Root DNS Server hints for recursive resolution
var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"199.9.14.201:53",   // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

// GeoIP Cache
type GeoIPCacheEntry struct {
	Country string
	Expires time.Time
}

var (
	geoIPCache   = make(map[string]GeoIPCacheEntry)
	geoIPCacheMu sync.RWMutex
)

// DNStap Channel
var (
	dnstapChan = make(chan string, 1000)
	dnstapOnce sync.Once
)

// accessLogMaxBytes is the size at which access.log is rotated. Query volume
// makes this file grow far faster than the process log, so it is rotated by
// size rather than by time.
const accessLogMaxBytes = 50 << 20 // 50 MiB

// accessLogBackups is how many rotated generations to keep (.1 .. .3).
const accessLogBackups = 3

// AccessEntry is one DNS query as persisted to access.log. Field names match
// dns.QueryLogEntry's JSON tags so the dashboard consumes both shapes with a
// single code path.
//
// Upstream and Dnssec are not recorded: the values are only known to the query
// pipeline at answer time and are omitted here rather than persisted as a
// guess. Readers substitute "—".
type AccessEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	ClientIP  string    `json:"client_ip"`
	Status    string    `json:"status"`
	ElapsedMs int64     `json:"elapsed_ms"`
}

// AdvancedEngine manages all 34 premium features for VortexDNS
type AdvancedEngine struct {
	cfg       *config.Config
	statsLock sync.Mutex
	history   []map[string]interface{}

	// accessLog is guarded by accessMu: WriteAccessLog is called from every DNS
	// handler goroutine, so the file handle and the byte counter must not be
	// touched concurrently.
	accessLog   *os.File
	accessPath  string
	accessBytes int64
	accessMu    sync.Mutex

	// Prometheus Metrics equivalents
	TotalQueries      int64
	BlockedQueries    int64
	DnssecSignatures  int64
	As112Queries      int64
	ChaosQueries      int64
	MalwareBlocked    int64
	ParentalBlocked   int64
	RebindingBlocked  int64
	GeoRoutingQueries int64

	// DNSSEC keys for mocking/validation signing
	dnssecKeyName string

	// Hosts File mapping
	hostsMap map[string]string
	hostsMu  sync.RWMutex

	// DoH / DoT / DoQ servers
	dohServer *http.Server
	dotServer *dns.Server
	doqLn     *quic.Listener

	// queryHook, when set, is called for every logged query so an external
	// store (SQLite) can persist it. Optional; nil means file-only logging.
	// Kept as a func to avoid importing the storage package here (import cycle).
	queryHook   func(domain, qType, clientIP, status string, elapsedMs int64, blocked bool)
	queryHookMu sync.RWMutex
}

// SetQueryHook registers a callback invoked on every WriteAccessLog call.
func (ae *AdvancedEngine) SetQueryHook(fn func(domain, qType, clientIP, status string, elapsedMs int64, blocked bool)) {
	ae.queryHookMu.Lock()
	ae.queryHook = fn
	ae.queryHookMu.Unlock()
}

var Instance *AdvancedEngine
var once sync.Once

// GetInstance returns the singleton AdvancedEngine instance
func GetInstance(cfg *config.Config) *AdvancedEngine {
	once.Do(func() {
		engine := &AdvancedEngine{
			cfg:           cfg,
			dnssecKeyName: "vortexdns.key.",
			hostsMap:      make(map[string]string),
		}

		if cfg.AccessLogPath != "" {
			engine.openAccessLog(cfg.AccessLogPath)
		}

		engine.ReloadHosts()

		if cfg.PrometheusEnabled {
			go engine.StartPrometheus()
		}

		Instance = engine
	})
	return Instance
}

func (ae *AdvancedEngine) StartPrometheus() {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP vortexdns_total_queries Total DNS queries processed.\n")
		fmt.Fprintf(w, "# TYPE vortexdns_total_queries counter\n")
		fmt.Fprintf(w, "vortexdns_total_queries %d\n", atomic.LoadInt64(&ae.TotalQueries))

		fmt.Fprintf(w, "# HELP vortexdns_blocked_queries Total DNS queries blocked.\n")
		fmt.Fprintf(w, "# TYPE vortexdns_blocked_queries counter\n")
		fmt.Fprintf(w, "vortexdns_blocked_queries %d\n", atomic.LoadInt64(&ae.BlockedQueries))
	})
	log.Printf("[Advanced] Starting Prometheus metrics on %s", ae.cfg.PrometheusAddress)
	_ = http.ListenAndServe(ae.cfg.PrometheusAddress, mux)
}

func (ae *AdvancedEngine) IsAllowedByACL(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return true
	}

	// 1. Check Explicit Deny
	for _, cidr := range ae.cfg.AclDeny {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ip) {
			return false
		}
		if cidr == clientIP {
			return false
		}
	}

	// 2. Check Explicit Allow (if configured, default deny others)
	if len(ae.cfg.AclAllow) > 0 {
		for _, cidr := range ae.cfg.AclAllow {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(ip) {
				return true
			}
			if cidr == clientIP {
				return true
			}
		}
		return false
	}

	return true
}

// 1. Reverse DNS (RDNS) Utility
func (ae *AdvancedEngine) ResolveRDNS(ipStr string) (string, error) {
	if !ae.cfg.ReverseDNSEnabled {
		return "", fmt.Errorf("RDNS disabled")
	}
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return "tidak-diketahui.rdns.local", nil
	}
	return names[0], nil
}

// 2. Whois Integration
func (ae *AdvancedEngine) QueryWhois(domain string) (string, error) {
	if !ae.cfg.WhoisEnabled {
		return "Whois integrasi dinonaktifkan di konfigurasi", nil
	}

	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	if cleanDomain == "" {
		return "", fmt.Errorf("domain kosong")
	}

	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 3*time.Second)
	if err != nil {
		return fmt.Sprintf("Domain: %s\nRegistrar: VortexDNS Synthetic WHOIS\nStatus: Active\nUpdated: %s", cleanDomain, time.Now().Format(time.RFC3339)), nil
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(cleanDomain + "\r\n"))
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Sprintf("Domain: %s\nRegistry: Fallback offline", cleanDomain), nil
	}
	return string(respBytes), nil
}

// 3. Safe Browsing / Malware protection
func (ae *AdvancedEngine) IsMalicious(domain string) bool {
	if !ae.cfg.SafeBrowsingEnabled {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	maliciousKeywords := []string{"phishing", "malware", "ransomware", "trojan", "keylogger", "virus-alert"}
	for _, kw := range maliciousKeywords {
		if strings.Contains(domain, kw) {
			atomic.AddInt64(&ae.MalwareBlocked, 1)
			return true
		}
	}
	return false
}

// 4. Parental Control / Adult content filtering
func (ae *AdvancedEngine) IsAdultContent(domain string) bool {
	if !ae.cfg.ParentalControlEnabled {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	adultKeywords := []string{"porn", "xxx", "sex", "gambling", "casino", "betting", "redtube", "pornhub"}
	for _, kw := range adultKeywords {
		if strings.Contains(domain, kw) {
			atomic.AddInt64(&ae.ParentalBlocked, 1)
			return true
		}
	}
	return false
}

// serviceDomains maps a blockable service ID to the domains it resolves through.
// This is the single source of truth for the dashboard's "Blocked Services" grid.
var serviceDomains = map[string][]string{
	"facebook":   {"facebook.com", "fbcdn.net", "fbsbx.com", "fb.com"},
	"instagram":  {"instagram.com", "cdninstagram.com"},
	"whatsapp":   {"whatsapp.com", "whatsapp.net"},
	"tiktok":     {"tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly"},
	"youtube":    {"youtube.com", "googlevideo.com", "youtu.be", "ytimg.com"},
	"twitter":    {"twitter.com", "twimg.com", "t.co", "x.com"},
	"snapchat":   {"snapchat.com", "sc-cdn.net", "snap.com"},
	"reddit":     {"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"},
	"discord":    {"discord.com", "discordapp.com", "discord.gg", "discordapp.net"},
	"telegram":   {"telegram.org", "telegram.me", "t.me", "telesco.pe"},
	"netflix":    {"netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net", "nflxso.net"},
	"spotify":    {"spotify.com", "scdn.co", "spotifycdn.com"},
	"twitch":     {"twitch.tv", "ttvnw.net", "jtvnw.net"},
	"steam":      {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
	"roblox":     {"roblox.com", "rbxcdn.com"},
	"epicgames":  {"epicgames.com", "unrealengine.com", "fortnite.com"},
	"torrent":    {"thepiratebay.org", "1337x.to", "rarbg.to", "nyaa.si", "torrentgalaxy.to"},
	"crypto":     {"binance.com", "coinbase.com", "coinmarketcap.com", "coin-hive.com", "cryptoloot.pro"},
	"dating":     {"tinder.com", "bumble.com", "okcupid.com", "badoo.com", "grindr.com"},
	"disneyplus": {"disneyplus.com", "disney-plus.net", "dssott.com"},
	"amazon":     {"amazon.com", "media-amazon.com", "ssl-images-amazon.com"},
	"pinterest":  {"pinterest.com", "pinimg.com"},
}

// GetServiceCatalog returns every service ID that can actually be blocked, sorted.
func GetServiceCatalog() []string {
	ids := make([]string, 0, len(serviceDomains))
	for id := range serviceDomains {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Blocked Services (per-app)
func (ae *AdvancedEngine) IsServiceBlocked(domain string) bool {
	if len(ae.cfg.BlockedServices) == 0 {
		return false
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	for _, srv := range ae.cfg.BlockedServices {
		domains, ok := serviceDomains[strings.ToLower(srv)]
		if !ok {
			continue
		}
		for _, d := range domains {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return true
			}
		}
	}
	return false
}

// Scheduled Filtering
func (ae *AdvancedEngine) IsScheduleBlocked(domain string) bool {
	if len(ae.cfg.ScheduleRules) == 0 {
		return false
	}

	now := time.Now()
	currentDay := strings.ToLower(now.Weekday().String()[:3]) // "mon", "tue", etc.
	currentTime := now.Format("15:04")                        // "HH:MM"

	for _, rule := range ae.cfg.ScheduleRules {
		// Check day match
		dayMatch := false
		for _, d := range rule.Days {
			if strings.ToLower(d) == currentDay || strings.ToLower(d) == "all" || strings.ToLower(d) == "everyday" {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			continue
		}

		// Check time match
		if currentTime >= rule.StartTime && currentTime <= rule.EndTime {
			// Inside blocked window, check if domain matches services
			// For simplicity, we reuse IsServiceBlocked logic with the rule's specific services
			originalServices := ae.cfg.BlockedServices
			ae.cfg.BlockedServices = rule.Services
			blocked := ae.IsServiceBlocked(domain)
			ae.cfg.BlockedServices = originalServices

			if blocked {
				return true
			}
		}
	}

	return false
}

// Transparent DNS Proxy (MITM/Hijack for VPN)
func (ae *AdvancedEngine) SetupTransparentProxy(dnsPort string) {
	if len(ae.cfg.TransparentProxyIfaces) == 0 {
		return
	}

	port := strings.TrimPrefix(dnsPort, ":")
	if port == "" {
		port = "53"
	}

	log.Printf("[Advanced] Setting up Transparent DNS Proxy on interfaces: %v to port %s", ae.cfg.TransparentProxyIfaces, port)

	for _, iface := range ae.cfg.TransparentProxyIfaces {
		// Clean up existing rules first to prevent duplicates
		ae.teardownInterfaceProxy(iface, port)

		// Redirect UDP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port).Run()
		// Redirect TCP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port).Run()
	}
}

func (ae *AdvancedEngine) TeardownTransparentProxy(dnsPort string) {
	if len(ae.cfg.TransparentProxyIfaces) == 0 {
		return
	}

	port := strings.TrimPrefix(dnsPort, ":")
	if port == "" {
		port = "53"
	}

	log.Println("[Advanced] Removing Transparent DNS Proxy rules...")
	for _, iface := range ae.cfg.TransparentProxyIfaces {
		ae.teardownInterfaceProxy(iface, port)
	}
}

func (ae *AdvancedEngine) teardownInterfaceProxy(iface, port string) {
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port).Run()
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", port).Run()
}

// 7. DNSSEC validation.
//
// This only ever verifies signatures that the upstream actually returned. It
// must never synthesise an RRSIG: a resolver that forges signatures would
// mislead validating clients, and a malformed signature makes the whole
// response unpackable so it can never be written back to the client.
func (ae *AdvancedEngine) SignDNSSEC(msg *dns.Msg) {
	if !ae.cfg.DnssecEnabled {
		return
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			ae.VerifyDNSSEC(msg)
			return
		}
	}
}

// VerifyDNSSEC performs real cryptographic verification of DNS signatures
func (ae *AdvancedEngine) VerifyDNSSEC(msg *dns.Msg) {
	if !ae.cfg.DnssecEnabled || len(msg.Answer) == 0 {
		return
	}

	var rrsigs []*dns.RRSIG
	rrsets := make(map[string][]dns.RR)

	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
		} else {
			key := fmt.Sprintf("%s:%d", rr.Header().Name, rr.Header().Rrtype)
			rrsets[key] = append(rrsets[key], rr)
		}
	}

	if len(rrsigs) == 0 {
		return
	}

	c := new(dns.Client)
	c.Timeout = 800 * time.Millisecond

	verifiedCount := 0
	for _, sig := range rrsigs {
		key := fmt.Sprintf("%s:%d", sig.Header().Name, sig.TypeCovered)
		rrset, exists := rrsets[key]
		if !exists || len(rrset) == 0 {
			continue
		}

		keyMsg := new(dns.Msg)
		keyMsg.SetQuestion(sig.SignerName, dns.TypeDNSKEY)
		keyMsg.MsgHdr.RecursionDesired = true

		resp, _, err := c.Exchange(keyMsg, "1.1.1.1:53")
		if err != nil || len(resp.Answer) == 0 {
			continue
		}

		for _, ans := range resp.Answer {
			if dnskey, ok := ans.(*dns.DNSKEY); ok {
				if sig.Verify(dnskey, rrset) == nil {
					verifiedCount++
					break
				}
			}
		}
	}

	if verifiedCount > 0 {
		msg.AuthenticatedData = true
		atomic.AddInt64(&ae.DnssecSignatures, int64(verifiedCount))
	} else {
		msg.AuthenticatedData = false
	}
}

// 10. Recursive Resolver helper (using root servers hints with fallback)
func (ae *AdvancedEngine) ResolveRecursively(req *dns.Msg) (*dns.Msg, error) {
	if !ae.cfg.RecursiveResolver {
		return nil, fmt.Errorf("recursive resolver disabled")
	}

	if len(req.Question) == 0 {
		return nil, fmt.Errorf("empty question")
	}

	q := req.Question[0]
	resp, err := ae.resolveIterative(q, rootServers, 0)
	if err == nil && resp != nil {
		resp.Id = req.Id
		return resp, nil
	}

	// Fallback to forwarding
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	resp, _, err = c.Exchange(req, "1.1.1.1:53")
	if err == nil {
		return resp, nil
	}
	return nil, err
}

func (ae *AdvancedEngine) resolveIterative(q dns.Question, servers []string, depth int) (*dns.Msg, error) {
	if depth > 10 {
		return nil, fmt.Errorf("depth limit exceeded")
	}

	c := new(dns.Client)
	c.Timeout = 1500 * time.Millisecond

	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.MsgHdr.RecursionDesired = false

	var lastErr error
	consecutiveErrors := 0
	for _, server := range servers {
		if consecutiveErrors >= 2 {
			break // Skip remaining root servers if we hit consecutive timeouts (offline/restricted)
		}

		serverAddr := server
		if !strings.Contains(serverAddr, ":") {
			serverAddr = serverAddr + ":53"
		}

		resp, _, err := c.Exchange(msg, serverAddr)
		if err != nil {
			lastErr = err
			consecutiveErrors++
			continue
		}
		consecutiveErrors = 0 // Reset on success

		if len(resp.Answer) > 0 || resp.Rcode == dns.RcodeNameError || resp.Rcode == dns.RcodeFormatError {
			return resp, nil
		}

		var nsRecords []*dns.NS
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsRecords = append(nsRecords, ns)
			}
		}

		if len(nsRecords) == 0 {
			return resp, nil
		}

		var nextServers []string
		for _, ns := range nsRecords {
			for _, rr := range resp.Extra {
				if a, ok := rr.(*dns.A); ok && a.Header().Name == ns.Ns {
					nextServers = append(nextServers, a.A.String())
				}
			}
		}

		if len(nextServers) == 0 {
			for _, ns := range nsRecords {
				nsQ := dns.Question{Name: ns.Ns, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				nsResp, err := ae.resolveIterative(nsQ, rootServers, depth+1)
				if err == nil && nsResp != nil {
					for _, rr := range nsResp.Answer {
						if a, ok := rr.(*dns.A); ok {
							nextServers = append(nextServers, a.A.String())
						}
					}
				}
				if len(nextServers) > 0 {
					break
				}
			}
		}

		if len(nextServers) > 0 {
			return ae.resolveIterative(q, nextServers, depth+1)
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("failed to resolve iteratively")
}

// 11. DNS64 Synthesis (IPv6 transition)
func (ae *AdvancedEngine) SynthesizeDNS64(ip4 net.IP) net.IP {
	if !ae.cfg.Dns64Enabled {
		return nil
	}

	ip6 := make(net.IP, 16)
	ip6[0] = 0x00
	ip6[1] = 0x64
	ip6[2] = 0xff
	ip6[3] = 0x9b
	copy(ip6[12:16], ip4.To4())
	return ip6
}

// 12. DNStap logging to Unix Socket asynchronously (non-blocking)
func (ae *AdvancedEngine) LogDNStap(domain string, qType uint16, clientIP string, elapsedMs int64) {
	if !ae.cfg.DnstapEnabled {
		return
	}

	dnstapOnce.Do(func() {
		go func() {
			for msg := range dnstapChan {
				socketPath := "vortex_db/dnstap.sock"
				conn, err := net.Dial("unix", socketPath)
				if err != nil {
					continue
				}
				_, _ = conn.Write([]byte(msg + "\n"))
				_ = conn.Close()
			}
		}()
	})

	logMsg := fmt.Sprintf(`{"timestamp":%d,"domain":"%s","type":%d,"client":"%s","rtt_ms":%d}`,
		time.Now().UnixNano(), domain, qType, clientIP, elapsedMs)

	log.Printf("[DNStap-Binary] %s", logMsg)

	select {
	case dnstapChan <- logMsg:
	default:
	}
}

// 13. AS112 Zones handling
func (ae *AdvancedEngine) IsAS112(domain string) bool {
	if !ae.cfg.As112Enabled {
		return false
	}
	d := strings.ToLower(domain)
	if strings.HasSuffix(d, "10.in-addr.arpa.") ||
		strings.HasSuffix(d, "168.192.in-addr.arpa.") ||
		strings.HasSuffix(d, "254.169.in-addr.arpa.") ||
		strings.HasSuffix(d, "empty.as112.arpa.") {
		atomic.AddInt64(&ae.As112Queries, 1)
		return true
	}
	return false
}

// 14. Access Log

// openAccessLog prepares the access log for appending, creating the parent
// directory when the configured path points somewhere that does not exist yet
// (for example /var/log/vortexdns on a fresh install).
func (ae *AdvancedEngine) openAccessLog(path string) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[Advanced] Access log directory %q unavailable: %v. Query history will not persist.", dir, err)
			return
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		// Surface this instead of failing silently: without it the dashboard's
		// query history simply appears empty with no explanation.
		log.Printf("[Advanced] Cannot open access log %q: %v. Query history will not persist.", path, err)
		return
	}

	ae.accessLog = file
	ae.accessPath = path
	if info, err := file.Stat(); err == nil {
		ae.accessBytes = info.Size()
	}
}

// anonymizeIP masks the trailing two octets of an IPv4 address, or the trailing
// ten bytes of an IPv6 address, matching AdGuard Home's behaviour. Returns the
// input unchanged when it does not parse as an address.
func anonymizeIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip4[2], ip4[3] = 0, 0
		return ip4.String()
	}
	for i := len(ip) - 10; i < len(ip); i++ {
		ip[i] = 0
	}
	return ip.String()
}

// WriteAccessLog appends one query to access.log as a single JSON object,
// rotating the file once it exceeds accessLogMaxBytes.
func (ae *AdvancedEngine) WriteAccessLog(domain, qType, clientIP, status string, elapsedMs int64) {
	ae.accessMu.Lock()
	defer ae.accessMu.Unlock()

	if ae.accessLog == nil {
		return
	}

	if ae.cfg != nil && ae.cfg.AnonymizeClientIP {
		clientIP = anonymizeIP(clientIP)
	}

	// Rotate before writing so the freshly opened file starts with this entry;
	// rotating after would push the triggering entry into the .1 backup and
	// leave the active file momentarily empty for readers.
	if ae.accessBytes >= accessLogMaxBytes {
		ae.rotateAccessLogLocked()
	}

	line, err := json.Marshal(AccessEntry{
		Timestamp: time.Now(),
		Domain:    strings.TrimSuffix(domain, "."),
		Type:      qType,
		ClientIP:  clientIP,
		Status:    status,
		ElapsedMs: elapsedMs,
	})
	if err != nil {
		return
	}

	n, err := ae.accessLog.Write(append(line, '\n'))
	if err != nil {
		return
	}
	ae.accessBytes += int64(n)

	// Mirror to external store (SQLite) if a hook is registered.
	ae.queryHookMu.RLock()
	hook := ae.queryHook
	ae.queryHookMu.RUnlock()
	if hook != nil {
		blocked := strings.HasPrefix(status, "Blocked")
		hook(strings.TrimSuffix(domain, "."), qType, clientIP, status, elapsedMs, blocked)
	}
}

// rotateAccessLogLocked shifts access.log to access.log.1, ageing the existing
// generations and discarding the oldest. Caller must hold accessMu.
func (ae *AdvancedEngine) rotateAccessLogLocked() {
	path := ae.accessPath
	if path == "" {
		return
	}

	_ = ae.accessLog.Close()
	ae.accessLog = nil

	// Drop the oldest generation, then shift the rest down: .2 -> .3, .1 -> .2.
	_ = os.Remove(fmt.Sprintf("%s.%d", path, accessLogBackups))
	for i := accessLogBackups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	if err := os.Rename(path, path+".1"); err != nil && !os.IsNotExist(err) {
		log.Printf("[Advanced] Access log rotation failed: %v", err)
	}

	ae.accessBytes = 0
	ae.openAccessLog(path)
}

// ReadAccessLog returns up to limit of the most recent persisted queries,
// newest first. Malformed lines are skipped rather than aborting the read, so a
// truncated final write (power loss mid-append) cannot hide the whole history.
func (ae *AdvancedEngine) ReadAccessLog(limit int) []AccessEntry {
	ae.accessMu.Lock()
	path := ae.accessPath
	ae.accessMu.Unlock()

	if path == "" || limit <= 0 {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Keep only the tail in memory: the file may be tens of megabytes while the
	// caller typically wants a few hundred rows.
	ring := make([]AccessEntry, 0, limit)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var entry AccessEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if len(ring) == limit {
			ring = ring[1:]
		}
		ring = append(ring, entry)
	}

	// Newest first, matching the live ring buffer's ordering.
	for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	return ring
}

// 15. Chaos Zone handler
func (ae *AdvancedEngine) HandleChaos(q dns.Question) *dns.Msg {
	atomic.AddInt64(&ae.ChaosQueries, 1)
	m := new(dns.Msg)
	m.Authoritative = true

	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: dns.TypeTXT,
		Class:  dns.ClassCHAOS,
		Ttl:    0,
	}

	name := strings.ToLower(q.Name)
	var txt string
	if strings.Contains(name, "version.bind") || strings.Contains(name, "version.server") {
		txt = "VortexDNS v1.2.0-Premium"
	} else if strings.Contains(name, "hostname.bind") || strings.Contains(name, "id.server") {
		h, _ := os.Hostname()
		if h == "" {
			h = "vortex-dns-node-1"
		}
		txt = h
	} else {
		txt = "VortexDNS CHAOS Service"
	}

	m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{txt}})
	return m
}

// 17. Split-Horizon Views selection
func (ae *AdvancedEngine) GetSplitHorizonUpstreams(clientIP string) []string {
	if len(ae.cfg.SplitHorizon) == 0 {
		return ae.cfg.UpstreamServers
	}

	client := net.ParseIP(clientIP)
	if client == nil {
		return ae.cfg.UpstreamServers
	}

	for cidr, upstreams := range ae.cfg.SplitHorizon {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(client) {
			return upstreams
		}
	}

	return ae.cfg.UpstreamServers
}

// 18. Kubernetes DNS Resolution Integration
func (ae *AdvancedEngine) ResolveKubernetes(domain string, qType uint16) *dns.Msg {
	if !ae.cfg.KubernetesEnabled {
		return nil
	}

	d := strings.ToLower(domain)
	if !strings.HasSuffix(d, "cluster.local.") {
		return nil
	}

	m := new(dns.Msg)
	m.Authoritative = true
	m.RecursionAvailable = true

	parts := strings.Split(strings.TrimSuffix(d, "."), ".")
	if len(parts) >= 4 {
		category := parts[len(parts)-3] // "svc" or "pod"

		if category == "svc" && qType == dns.TypeA {
			sum := 0
			for _, char := range parts[0] {
				sum += int(char)
			}
			ipStr := fmt.Sprintf("10.96.1.%d", sum%254+1)
			hdr := dns.RR_Header{
				Name:   domain,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			}
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(ipStr)})
			return m
		}

		if category == "pod" && qType == dns.TypeA {
			podIP := strings.ReplaceAll(parts[0], "-", ".")
			if parsedIP := net.ParseIP(podIP); parsedIP != nil {
				hdr := dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				}
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: parsedIP})
				return m
			}
		}
	}

	m.SetRcode(msgForK8s(domain), dns.RcodeNameError)
	return m
}

func msgForK8s(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// 19. Hosts file integration
func (ae *AdvancedEngine) ReloadHosts() {
	if !ae.cfg.HostsFileEnabled {
		return
	}
	ae.hostsMu.Lock()
	defer ae.hostsMu.Unlock()

	ae.hostsMap = make(map[string]string)

	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		ae.hostsMap["my.vortex.local."] = "127.0.0.1"
		ae.hostsMap["router.local."] = "192.168.1.1"
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ip := parts[0]
			for _, hostname := range parts[1:] {
				fqdn := dns.Fqdn(strings.ToLower(hostname))
				ae.hostsMap[fqdn] = ip
			}
		}
	}
}

func (ae *AdvancedEngine) LookupHosts(domain string) string {
	if !ae.cfg.HostsFileEnabled {
		return ""
	}
	ae.hostsMu.RLock()
	defer ae.hostsMu.RUnlock()
	return ae.hostsMap[dns.Fqdn(domain)]
}

// Conditional Forwarding
func (ae *AdvancedEngine) GetConditionalUpstreams(domain string) []string {
	if len(ae.cfg.ConditionalForwarding) == 0 {
		return nil
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, rule := range ae.cfg.ConditionalForwarding {
		if strings.HasSuffix(domain, rule.Domain) {
			return rule.Upstreams
		}
	}
	return nil
}

// 22. DNS Zone Management (Authoritative record search + Wildcard)
func (ae *AdvancedEngine) LookupAuthoritative(domain string, qType uint16) []dns.RR {
	fqdn := dns.Fqdn(strings.ToLower(domain))
	var answers []dns.RR

	for _, rec := range ae.cfg.ZoneRecords {
		match := false
		recName := dns.Fqdn(strings.ToLower(rec.Name))

		if recName == fqdn {
			match = true
		} else if ae.cfg.WildcardZones && strings.HasPrefix(recName, "*.") {
			suffix := strings.TrimPrefix(recName, "*.")
			if strings.HasSuffix(fqdn, suffix) {
				match = true
			}
		}

		if match {
			hdr := dns.RR_Header{
				Name:  fqdn,
				Class: dns.ClassINET,
				Ttl:   rec.TTL,
			}

			switch strings.ToUpper(rec.Type) {
			case "A":
				if qType == dns.TypeA || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeA
					answers = append(answers, &dns.A{Hdr: hdr, A: net.ParseIP(rec.Value)})
				}
			case "AAAA":
				if qType == dns.TypeAAAA || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeAAAA
					answers = append(answers, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(rec.Value)})
				}
			case "CNAME":
				if qType == dns.TypeCNAME || qType == dns.TypeA || qType == dns.TypeAAAA || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeCNAME
					answers = append(answers, &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rec.Value)})
				}
			case "MX":
				if qType == dns.TypeMX || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeMX
					answers = append(answers, &dns.MX{
						Hdr:        hdr,
						Preference: 10,
						Mx:         dns.Fqdn(rec.Value),
					})
				}
			case "TXT":
				if qType == dns.TypeTXT || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeTXT
					answers = append(answers, &dns.TXT{
						Hdr: hdr,
						Txt: []string{rec.Value},
					})
				}
			case "SRV":
				if qType == dns.TypeSRV || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeSRV
					// basic parse "priority weight port target"
					parts := strings.Fields(rec.Value)
					if len(parts) >= 4 {
						var prio, weight, port uint16
						fmt.Sscanf(parts[0], "%d", &prio)
						fmt.Sscanf(parts[1], "%d", &weight)
						fmt.Sscanf(parts[2], "%d", &port)
						answers = append(answers, &dns.SRV{
							Hdr:      hdr,
							Priority: prio,
							Weight:   weight,
							Port:     port,
							Target:   dns.Fqdn(parts[3]),
						})
					}
				}
			case "NS":
				if qType == dns.TypeNS || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeNS
					answers = append(answers, &dns.NS{
						Hdr: hdr,
						Ns:  dns.Fqdn(rec.Value),
					})
				}
			case "SOA":
				if qType == dns.TypeSOA || qType == dns.TypeANY {
					hdr.Rrtype = dns.TypeSOA
					parts := strings.Fields(rec.Value)
					if len(parts) >= 2 {
						answers = append(answers, &dns.SOA{
							Hdr:     hdr,
							Ns:      dns.Fqdn(parts[0]),
							Mbox:    dns.Fqdn(parts[1]),
							Serial:  1,
							Refresh: 86400,
							Retry:   7200,
							Expire:  3600000,
							Minttl:  172800,
						})
					}
				}
			case "NODATA":
				// Handle NODATA by just returning true match without answers.
				// The server logic will respond with NOERROR, 0 answers.
			}
		}
	}
	return answers
}

// 24. DNS Rebinding Protection (IPv4 A & IPv6 AAAA)
func (ae *AdvancedEngine) IsRebindingResponse(msg *dns.Msg) bool {
	if !ae.cfg.DnsRebindingEnabled || msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		if aRecord, ok := rr.(*dns.A); ok {
			ip := aRecord.A
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				atomic.AddInt64(&ae.RebindingBlocked, 1)
				return true
			}
		}
		if aaaaRecord, ok := rr.(*dns.AAAA); ok {
			ip := aaaaRecord.AAAA
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				atomic.AddInt64(&ae.RebindingBlocked, 1)
				return true
			}
		}
	}
	return false
}

// 27. Geo-based DNS routing with dynamic caching and API fallback
func (ae *AdvancedEngine) ResolveGeoDNS(domain string, clientIP string, qType uint16) []dns.RR {
	if !ae.cfg.GeoDns {
		return nil
	}

	atomic.AddInt64(&ae.GeoRoutingQueries, 1)
	country := getCountryFromIP(clientIP)

	fqdn := dns.Fqdn(strings.ToLower(domain))
	hdr := dns.RR_Header{
		Name:  fqdn,
		Class: dns.ClassINET,
		Ttl:   60,
	}

	var answers []dns.RR
	if qType == dns.TypeA {
		hdr.Rrtype = dns.TypeA
		var targetIP string
		switch country {
		case "US":
			targetIP = "104.244.42.1"
		case "SG":
			targetIP = "128.199.64.1"
		default:
			targetIP = "103.22.200.1" // ID / Default
		}
		answers = append(answers, &dns.A{Hdr: hdr, A: net.ParseIP(targetIP)})
	}
	return answers
}

func getCountryFromIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "ID"
	}

	if ip.IsPrivate() || ip.IsLoopback() {
		return "ID"
	}

	ip4 := ip.To4()
	if ip4 != nil {
		firstByte := ip4[0]
		switch firstByte {
		case 36, 103, 110, 111, 112, 114, 115, 116, 117, 118, 120, 125, 139, 140, 180, 182, 202, 203:
			return "ID"
		case 8, 23, 34, 35, 40, 44, 45, 47, 50, 52, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 172, 173, 174, 184, 192, 198, 204, 205, 206, 207, 208, 209:
			return "US"
		case 13, 43, 101, 119, 122, 128, 175, 210, 218:
			return "SG"
		}
	}

	geoIPCacheMu.RLock()
	entry, exists := geoIPCache[ipStr]
	geoIPCacheMu.RUnlock()
	if exists && time.Now().Before(entry.Expires) {
		return entry.Country
	}

	client := &http.Client{
		Timeout: 150 * time.Millisecond,
	}
	resp, err := client.Get("http://ip-api.com/json/" + ipStr + "?fields=status,countryCode")
	if err == nil {
		defer resp.Body.Close()
		var res struct {
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
		}
		if json.NewDecoder(resp.Body).Decode(&res) == nil && res.Status == "success" {
			geoIPCacheMu.Lock()
			geoIPCache[ipStr] = GeoIPCacheEntry{
				Country: res.CountryCode,
				Expires: time.Now().Add(24 * time.Hour),
			}
			geoIPCacheMu.Unlock()
			return res.CountryCode
		}
	}

	lastByte := ip[len(ip)-1]
	if lastByte%3 == 1 {
		return "US"
	} else if lastByte%3 == 2 {
		return "SG"
	}
	return "ID"
}

// 30. Auto-PTR generation
func (ae *AdvancedEngine) HandleAutoPTR(q dns.Question) *dns.Msg {
	if !ae.cfg.AutoPtr {
		return nil
	}

	if strings.HasSuffix(strings.ToLower(q.Name), ".in-addr.arpa.") {
		m := new(dns.Msg)
		m.Authoritative = true
		hdr := dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		m.Answer = append(m.Answer, &dns.PTR{
			Hdr: hdr,
			Ptr: "device-auto-ptr.vortexdns.local.",
		})
		return m
	}
	return nil
}

// 34. Long-term statistics collection
func (ae *AdvancedEngine) RecordLongTermStat(domain, qType, clientIP, status string) {
	if !ae.cfg.LongTermStats {
		return
	}
	ae.statsLock.Lock()
	defer ae.statsLock.Unlock()

	ae.history = append(ae.history, map[string]interface{}{
		"time":   time.Now().Unix(),
		"domain": domain,
		"type":   qType,
		"client": clientIP,
		"status": status,
	})

	// Time-based retention: drop entries older than the configured window.
	// 0 disables time pruning (only the count cap below applies).
	if ae.cfg.StatsRetentionHours > 0 {
		cutoff := time.Now().Add(-time.Duration(ae.cfg.StatsRetentionHours) * time.Hour).Unix()
		idx := 0
		for idx < len(ae.history) {
			if ts, ok := ae.history[idx]["time"].(int64); ok && ts >= cutoff {
				break
			}
			idx++
		}
		if idx > 0 {
			ae.history = ae.history[idx:]
		}
	}

	if len(ae.history) > 10000 {
		ae.history = ae.history[1:]
	}
}

func (ae *AdvancedEngine) GetLongTermHistory() []map[string]interface{} {
	ae.statsLock.Lock()
	defer ae.statsLock.Unlock()
	return ae.history
}

// ResetStats zeroes the advanced counters and clears the long-term history
// buffer. Counters use atomic stores; history is guarded by statsLock.
func (ae *AdvancedEngine) ResetStats() {
	atomic.StoreInt64(&ae.TotalQueries, 0)
	atomic.StoreInt64(&ae.BlockedQueries, 0)
	atomic.StoreInt64(&ae.DnssecSignatures, 0)
	atomic.StoreInt64(&ae.MalwareBlocked, 0)
	atomic.StoreInt64(&ae.ParentalBlocked, 0)
	atomic.StoreInt64(&ae.RebindingBlocked, 0)

	ae.statsLock.Lock()
	ae.history = nil
	ae.statsLock.Unlock()
}

// TLS Helpers
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"VortexDNS Premium Authority"},
		},
		NotBefore:             notBefore,
		DNSNames:              []string{"localhost", "127.0.0.1", "192.168.100.106"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.100.106")},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func (ae *AdvancedEngine) GetTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if ae.cfg.TlsCertPath != "" && ae.cfg.TlsKeyPath != "" {
		cert, err = tls.LoadX509KeyPair(ae.cfg.TlsCertPath, ae.cfg.TlsKeyPath)
		if err != nil {
			log.Printf("[Advanced] Failed to load keypair: %v. Generating self-signed fallback.", err)
			cert, err = generateSelfSignedCert()
		}
	} else {
		cert, err = generateSelfSignedCert()
	}

	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// DoQ Response Writer
type doqResponseWriter struct {
	conn   *quic.Conn
	stream *quic.Stream
}

func (dw *doqResponseWriter) LocalAddr() net.Addr         { return dw.conn.LocalAddr() }
func (dw *doqResponseWriter) RemoteAddr() net.Addr        { return dw.conn.RemoteAddr() }
func (dw *doqResponseWriter) Close() error                { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error           { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(b bool)       {}
func (dw *doqResponseWriter) Hijack()                     {}
func (dw *doqResponseWriter) Write(b []byte) (int, error) { return dw.stream.Write(b) }
func (dw *doqResponseWriter) WriteMsg(m *dns.Msg) error {
	bytes, err := m.Pack()
	if err != nil {
		return err
	}
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(bytes)))
	_, _ = dw.stream.Write(prefix)
	_, err = dw.stream.Write(bytes)
	return err
}

// StartDoQ handles setting up the DNS-over-QUIC (DoQ) server listener
func (ae *AdvancedEngine) StartDoQ(dnsHandler dns.HandlerFunc, tlsConfig *tls.Config) {
	if !ae.cfg.DoQEnabled || ae.cfg.DoQAddress == "" {
		return
	}

	cloned := tlsConfig.Clone()
	cloned.NextProtos = []string{"doq", "doq-i02", "dq", "doq-i00", "doq-i01", "doq-i11"}

	go func() {
		log.Printf("[Advanced] Starting DoQ (DNS-over-QUIC) on %s", ae.cfg.DoQAddress)
		ln, err := quic.ListenAddr(ae.cfg.DoQAddress, cloned, &quic.Config{
			MaxIdleTimeout: 5 * time.Second,
		})
		if err != nil {
			log.Printf("[Advanced] DoQ listener failed: %v", err)
			return
		}
		ae.doqLn = ln

		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(c *quic.Conn) {
				for {
					stream, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func(s *quic.Stream) {
						defer s.Close()
						lenBuf := make([]byte, 2)
						_, err := io.ReadFull(s, lenBuf)
						if err != nil {
							return
						}
						msgLen := binary.BigEndian.Uint16(lenBuf)
						msgBuf := make([]byte, msgLen)
						_, err = io.ReadFull(s, msgBuf)
						if err != nil {
							return
						}

						msg := new(dns.Msg)
						if err := msg.Unpack(msgBuf); err != nil {
							return
						}

						dw := &doqResponseWriter{conn: c, stream: s}
						dnsHandler(dw, msg)
					}(stream)
				}
			}(conn)
		}
	}()
}

// StartDHCP boots a lightweight offline DHCP server on port 67 (fallback 6767)
func (ae *AdvancedEngine) StartDHCP() {
	if !ae.cfg.DhcpEnabled {
		return
	}

	go func() {
		log.Printf("[Advanced] Starting DHCP Server listening on port 67...")
		conn, err := net.ListenPacket("udp4", "0.0.0.0:67")
		if err != nil {
			log.Printf("[Advanced] Failed to bind to DHCP port 67 (requires root). Falling back to port 6767: %v", err)
			conn, err = net.ListenPacket("udp4", "0.0.0.0:6767")
			if err != nil {
				log.Printf("[Advanced] DHCP Server startup failed: %v", err)
				return
			}
		}
		defer conn.Close()

		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}

			if n < 240 {
				continue
			}

			if buf[236] != 0x63 || buf[237] != 0x82 || buf[238] != 0x53 || buf[239] != 0x63 {
				continue
			}

			xid := buf[4:8]
			chaddr := buf[28:34]

			msgType := byte(0)
			optIdx := 240
			for optIdx < n {
				optCode := buf[optIdx]
				if optCode == 255 {
					break
				}
				if optCode == 0 {
					optIdx++
					continue
				}
				optLen := int(buf[optIdx+1])
				if optIdx+2+optLen > n {
					break
				}
				if optCode == 53 && optLen == 1 {
					msgType = buf[optIdx+2]
				}
				optIdx += 2 + optLen
			}

			if msgType == 1 { // DHCPDISCOVER
				reply := make([]byte, 300)
				reply[0] = 2
				reply[1] = 1
				reply[2] = 6
				copy(reply[4:8], xid)
				copy(reply[28:34], chaddr)
				copy(reply[16:20], []byte{192, 168, 1, 150})
				copy(reply[236:240], []byte{0x63, 0x82, 0x53, 0x63})

				opts := []byte{
					53, 1, 2, // DHCPOFFER
					1, 4, 255, 255, 255, 0,
					3, 4, 192, 168, 1, 1,
					6, 4, 192, 168, 1, 1,
					51, 4, 0, 0, 28, 128,
					255,
				}
				copy(reply[240:], opts)

				dst, _ := net.ResolveUDPAddr("udp4", "255.255.255.255:68")
				_, _ = conn.WriteTo(reply[:240+len(opts)], dst)

			} else if msgType == 3 { // DHCPREQUEST
				reply := make([]byte, 300)
				reply[0] = 2
				reply[1] = 1
				reply[2] = 6
				copy(reply[4:8], xid)
				copy(reply[28:34], chaddr)
				copy(reply[16:20], []byte{192, 168, 1, 150})
				copy(reply[236:240], []byte{0x63, 0x82, 0x53, 0x63})

				opts := []byte{
					53, 1, 5, // DHCPACK
					1, 4, 255, 255, 255, 0,
					3, 4, 192, 168, 1, 1,
					6, 4, 192, 168, 1, 1,
					51, 4, 0, 0, 28, 128,
					255,
				}
				copy(reply[240:], opts)

				dst, _ := net.ResolveUDPAddr("udp4", "255.255.255.255:68")
				_, _ = conn.WriteTo(reply[:240+len(opts)], dst)
			}
		}
	}()
}

// DoH (DNS over HTTPS) and DoT (DNS over TLS) launching capabilities
func (ae *AdvancedEngine) StartDoHAndDoT(dnsHandler dns.HandlerFunc) {
	tlsConfig, err := ae.GetTLSConfig()
	if err != nil {
		log.Printf("[Advanced] Failed to configure TLS: %v", err)
	}

	if ae.cfg.DoHEnabled && ae.cfg.DoHAddress != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
			var body []byte
			var err error
			if r.Method == "GET" {
				dnsParam := r.URL.Query().Get("dns")
				body, err = base64.RawURLEncoding.DecodeString(dnsParam)
				if err != nil {
					body, err = base64.URLEncoding.DecodeString(dnsParam)
				}
			} else if r.Method == "POST" {
				body, err = io.ReadAll(r.Body)
			}

			if err != nil || len(body) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			respWriter := &dohResponseWriter{
				remoteAddr: r.RemoteAddr,
				localAddr:  r.Host,
			}

			dnsHandler(respWriter, msg)

			if respWriter.msg != nil {
				respBytes, err := respWriter.msg.Pack()
				if err == nil {
					w.Header().Set("Content-Type", "application/dns-message")
					w.Header().Set("Cache-Control", "max-age=60")
					_, _ = w.Write(respBytes)
					return
				}
			}
			w.WriteHeader(http.StatusInternalServerError)
		})

		ae.dohServer = &http.Server{
			Addr:      ae.cfg.DoHAddress,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("[Advanced] Starting DoH (DNS-over-HTTPS) on %s", ae.cfg.DoHAddress)
			if tlsConfig != nil {
				_ = ae.dohServer.ListenAndServeTLS("", "")
			} else {
				_ = ae.dohServer.ListenAndServe()
			}
		}()
	}

	if ae.cfg.DoTEnabled && ae.cfg.DoTAddress != "" && tlsConfig != nil {
		ae.dotServer = &dns.Server{
			Addr:      ae.cfg.DoTAddress,
			Net:       "tcp-tls",
			Handler:   dnsHandler,
			TLSConfig: tlsConfig,
		}
		go func() {
			log.Printf("[Advanced] Starting DoT (DNS-over-TLS) on %s", ae.cfg.DoTAddress)
			_ = ae.dotServer.ListenAndServe()
		}()
	}

	if ae.cfg.DoQEnabled && ae.cfg.DoQAddress != "" && tlsConfig != nil {
		ae.StartDoQ(dnsHandler, tlsConfig)
	}

	if ae.cfg.DhcpEnabled {
		ae.StartDHCP()
	}
}

func (ae *AdvancedEngine) StopDoHAndDoT() {
	if ae.dohServer != nil {
		_ = ae.dohServer.Shutdown(context.Background())
	}
	if ae.dotServer != nil {
		_ = ae.dotServer.Shutdown()
	}
	if ae.doqLn != nil {
		_ = ae.doqLn.Close()
	}
}

// SetConfig updates the engine's configuration at runtime
func (ae *AdvancedEngine) SetConfig(cfg *config.Config) {
	ae.cfg = cfg
}

type dohResponseWriter struct {
	remoteAddr string
	localAddr  string
	msg        *dns.Msg
}

func (dw *dohResponseWriter) LocalAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", dw.localAddr)
	return a
}
func (dw *dohResponseWriter) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", dw.remoteAddr)
	return a
}
func (dw *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	dw.msg = m
	return nil
}
func (dw *dohResponseWriter) Write(b []byte) (int, error) { return 0, nil }
func (dw *dohResponseWriter) Close() error                { return nil }
func (dw *dohResponseWriter) TsigStatus() error           { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(b bool)       {}
func (dw *dohResponseWriter) Hijack()                     {}
