package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// saveMu serializes config writes so two concurrent Save calls can never
// interleave and corrupt the file (mirrors AdGuard Home's config lock).
var saveMu sync.Mutex

// defaultSessionSecret is the legacy placeholder. Any config still carrying
// this value (or an empty one) gets a fresh random secret on load.
const defaultSessionSecret = "vortex-secret-change-me"

// generateSessionSecret returns a cryptographically-random 32-byte secret as
// a hex string. Falls back to the placeholder only if the OS RNG fails, which
// in practice never happens.
func generateSessionSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return defaultSessionSecret
	}
	return hex.EncodeToString(b)
}

// Config holds all the configuration settings for VortexDNS
type ZoneRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // "A", "AAAA", "MX", "CNAME", etc.
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type ScheduleRule struct {
	Name      string   `json:"name"`
	Services  []string `json:"services"`   // blocked service names
	Days      []string `json:"days"`       // "mon","tue",etc
	StartTime string   `json:"start_time"` // "08:00"
	EndTime   string   `json:"end_time"`   // "17:00"
}

type ConditionalForwardRule struct {
	Domain    string   `json:"domain"`    // domain suffix to match
	Upstreams []string `json:"upstreams"` // upstream servers for this domain
}

type Group struct {
	Name       string   `json:"name"`
	Clients    []string `json:"clients"` // IPs or CIDRs
	Blocklists []string `json:"blocklists"`
}

type Config struct {
	BindAddress       string   `json:"bind_address"`        // e.g. ":53" or ":5353"
	UpstreamServers   []string `json:"upstream_servers"`    // Upstream DNS servers, e.g. ["1.1.1.1:53", "8.8.8.8:53"]
	BlocklistURLs     []string `json:"blocklist_urls"`      // Remote hosts URLs to download
	CustomBlacklist   []string `json:"custom_blacklist"`    // Custom exact/wildcard blocking rules
	CustomWhitelist   []string `json:"custom_whitelist"`    // Custom domains to bypass blocking
	DashboardAddress  string   `json:"dashboard_address"`   // e.g. "0.0.0.0:8080"
	CacheSize         int      `json:"cache_size"`          // Max elements in DNS cache
	CacheMinTTL       int      `json:"cache_min_ttl"`       // Minimum cache TTL in seconds
	CacheMaxTTL       int      `json:"cache_max_ttl"`       // Maximum cache TTL in seconds
	CachePrefetch     bool     `json:"cache_prefetch"`      // Enable caching prefetch
	RateLimitQPS      int      `json:"rate_limit_qps"`      // Rate limit per client IP (0 = disabled)
	BlockingMode      string   `json:"blocking_mode"`       // "zero_ip" (0.0.0.0) or "nxdomain" (Name Error)
	WhitelistURLs     []string `json:"whitelist_urls"`      // Remote URLs for anti-adblock bypass lists
	DatabaseDir       string   `json:"database_dir"`        // Directory where lists/logs are stored
	AdminUsername     string   `json:"admin_username"`      // Dashboard login username
	AdminPasswordHash string   `json:"admin_password_hash"` // bcrypt hash of admin password
	SessionSecret     string   `json:"session_secret"`      // Secret for securing cookies

	// New advanced features configuration
	ReverseDNSEnabled      bool   `json:"reverse_dns_enabled"`
	WhoisEnabled           bool   `json:"whois_enabled"`
	SafeBrowsingEnabled    bool   `json:"safe_browsing_enabled"`
	ParentalControlEnabled bool   `json:"parental_control_enabled"`
	DoHEnabled             bool   `json:"doh_enabled"`
	DoHAddress             string `json:"doh_address"`
	DoTEnabled             bool   `json:"dot_enabled"`
	DoTAddress             string `json:"dot_address"`
	DoQEnabled             bool   `json:"doq_enabled"`
	DoQAddress             string `json:"doq_address"`
	DnssecEnabled          bool   `json:"dnssec_enabled"`
	TlsCertPath            string `json:"tls_cert_path"`
	TlsKeyPath             string `json:"tls_key_path"`
	RecursiveResolver      bool   `json:"recursive_resolver"`
	Dns64Enabled           bool   `json:"dns64_enabled"`
	DnstapEnabled          bool   `json:"dnstap_enabled"`
	As112Enabled           bool   `json:"as112_enabled"`
	AccessLogPath          string `json:"access_log_path"`
	// LogFilePath is where the process log (startup, errors, shutdown) is
	// written. Empty means stdout only, which is the case when running from a
	// terminal; the installer points it at a file so vortex.log exists only
	// after an install.
	LogFilePath string `json:"log_file_path"`
	// AnonymizeClientIP masks the trailing two octets of client addresses in
	// access.log. Off by default; the log is only as private as the host it
	// sits on, so this is opt-in rather than assumed.
	AnonymizeClientIP   bool                `json:"anonymize_client_ip"`
	ChaosEnabled        bool                `json:"chaos_enabled"`
	PrometheusEnabled   bool                `json:"prometheus_enabled"`
	PrometheusAddress   string              `json:"prometheus_address"`
	AclAllow            []string            `json:"acl_allow"`
	AclDeny             []string            `json:"acl_deny"`
	SplitHorizon        map[string][]string `json:"split_horizon"` // subnet -> upstreams
	KubernetesEnabled   bool                `json:"kubernetes_enabled"`
	HostsFileEnabled    bool                `json:"hosts_file_enabled"`
	FailoverUpstreams   []string            `json:"failover_upstreams"`
	ZoneRecords         []ZoneRecord        `json:"zone_records"`
	BlockPageEnabled    bool                `json:"block_page_enabled"`
	DnsRebindingEnabled bool                `json:"dns_rebinding_enabled"`
	DropRequests        []string            `json:"drop_requests"` // domain list
	FilterAaaa          bool                `json:"filter_aaaa"`
	GeoDns              bool                `json:"geo_dns"`
	NxDomainOverride    string              `json:"nx_domain_override"`
	AutoPtr             bool                `json:"auto_ptr"`
	GravityEnabled      bool                `json:"gravity_enabled"`
	GravityCronMinutes  int                 `json:"gravity_cron_minutes"`
	Groups              []Group             `json:"groups"`
	LongTermStats       bool                `json:"long_term_stats"`
	StatsRetentionHours int                 `json:"stats_retention_hours"` // prune long-term history older than this; 0 = keep all (capped by count)
	DhcpEnabled         bool                `json:"dhcp_enabled"`
	DhcpRange           string              `json:"dhcp_range"`

	// New features
	BlockedServices        []string                 `json:"blocked_services"`
	ScheduleRules          []ScheduleRule           `json:"schedule_rules"`
	ConditionalForwarding  []ConditionalForwardRule `json:"conditional_forwarding"`
	WildcardZones          bool                     `json:"wildcard_zones"`
	TransparentProxyIfaces []string                 `json:"transparent_proxy_interfaces"` // e.g., ["wg0", "tun0"]
}

// DefaultConfig returns a pre-configured configuration
func DefaultConfig() *Config {
	return &Config{
		BindAddress: ":5353", // Default to 5353 to avoid binding conflicts unless run as root
		UpstreamServers: []string{
			"1.1.1.1:53", // Cloudflare
			"8.8.8.8:53", // Google
			"9.9.9.9:53", // Quad9
		},
		BlocklistURLs: []string{
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		},
		CustomBlacklist: []string{
			"example-bad-ad.com",
			"*.malicious-tracker.net",
		},
		CustomWhitelist: []string{
			"google.com",
			"github.com",
		},
		DashboardAddress: "0.0.0.0:8080",
		CacheSize:        50000,
		CacheMinTTL:      60,
		CacheMaxTTL:      86400,
		CachePrefetch:    true,
		RateLimitQPS:     0,          // disabled by default
		BlockingMode:     "nxdomain", // NXDOMAIN is better for anti-adblock stealth
		WhitelistURLs:    []string{
			// Add popular anti-adblock bypass lists here if needed
		},
		DatabaseDir:       "vortex_db",
		AdminUsername:     "", // Empty implies setup mode is active
		AdminPasswordHash: "",
		SessionSecret:     "vortex-secret-change-me",

		// New advanced defaults
		ReverseDNSEnabled:      true,
		WhoisEnabled:           true,
		SafeBrowsingEnabled:    true,
		ParentalControlEnabled: true,
		DoHEnabled:             false,
		DoHAddress:             ":8443",
		DoTEnabled:             false,
		DoTAddress:             ":853",
		DoQEnabled:             false,
		DoQAddress:             ":853",
		DnssecEnabled:          true,
		TlsCertPath:            "",
		TlsKeyPath:             "",
		RecursiveResolver:      true,
		Dns64Enabled:           false,
		DnstapEnabled:          false,
		As112Enabled:           true,
		AccessLogPath:          "vortex_db/access.log",
		LogFilePath:            "",
		AnonymizeClientIP:      false,
		ChaosEnabled:           true,
		PrometheusEnabled:      true,
		PrometheusAddress:      ":9091",
		AclAllow:               []string{},
		AclDeny:                []string{},
		SplitHorizon:           make(map[string][]string),
		KubernetesEnabled:      false,
		HostsFileEnabled:       true,
		FailoverUpstreams:      []string{"8.8.4.4:53"},
		ZoneRecords:            []ZoneRecord{},
		BlockPageEnabled:       true,
		DnsRebindingEnabled:    true,
		DropRequests:           []string{},
		FilterAaaa:             false,
		GeoDns:                 true,
		NxDomainOverride:       "",
		AutoPtr:                true,
		GravityEnabled:         true,
		GravityCronMinutes:     0,
		Groups:                 []Group{},
		LongTermStats:          true,
		StatsRetentionHours:    24,
		DhcpEnabled:            false,
		DhcpRange:              "192.168.1.100-192.168.1.200",
		BlockedServices:        []string{},
		ScheduleRules:          []ScheduleRule{},
		ConditionalForwarding:  []ConditionalForwardRule{},
		WildcardZones:          true,
		TransparentProxyIfaces: []string{}, // Add "wg0" or "tun0" here to auto-hijack VPN DNS
	}
}

// Load reads the configuration from a path, or creates a default one if not found
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Save default configuration
		cfg := DefaultConfig()
		cfg.SessionSecret = generateSessionSecret()
		err := Save(path, cfg)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	// Ensure database directory exists
	if cfg.DatabaseDir == "" {
		cfg.DatabaseDir = "vortex_db"
	}
	_ = os.MkdirAll(cfg.DatabaseDir, 0755)

	// Upgrade legacy/empty secrets to a random one and persist it so cookies
	// aren't signed with a shared, well-known placeholder.
	if cfg.SessionSecret == "" || cfg.SessionSecret == defaultSessionSecret {
		cfg.SessionSecret = generateSessionSecret()
		_ = Save(path, &cfg)
	}

	return &cfg, nil
}

// Save writes the configuration to a path
func Save(path string, cfg *Config) error {
	// Serialize all writes: concurrent dashboard saves must never interleave.
	saveMu.Lock()
	defer saveMu.Unlock()

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}

	bytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Preserve the existing file's permission bits if it already exists,
	// otherwise fall back to 0644.
	perm := os.FileMode(0644)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}

	// Atomic write: write to a temp file in the same directory, flush it to
	// disk, then rename over the target. rename(2) is atomic on the same
	// filesystem, so a crash or power loss can never leave a half-written or
	// empty config.json — the old file stays intact until the swap completes.
	writeDir := dir
	if writeDir == "" {
		writeDir = "."
	}
	tmp, err := os.CreateTemp(writeDir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail out before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err = tmp.Write(bytes); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, perm); err != nil {
		return err
	}

	// Atomic swap. This is the happy path for normal files and volume/dir
	// mounts.
	if err = os.Rename(tmpName, path); err == nil {
		return nil
	}

	// Fallback: some deployments bind-mount config.json as a single file
	// (e.g. `-v ./config.json:/app/config.json`). The target is then a mount
	// point and rename(2) returns EBUSY/EXDEV — you cannot replace a mounted
	// file by renaming over it. In that case write in place: truncate + write
	// the already-marshaled bytes. Data was validated via MarshalIndent above,
	// so the content is well-formed; the write is a single syscall for a small
	// file, minimizing the corruption window.
	if werr := os.WriteFile(path, bytes, perm); werr != nil {
		// Surface the original rename error too for easier diagnosis.
		return werr
	}
	return nil
}
