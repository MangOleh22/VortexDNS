package scanner

import (
	"encoding/json"
	"time"
)

// ScanStatus represents the lifecycle state of a scan.
type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// Severity represents finding severity.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "informational"
)

// ScanConfig specifies crawl and execution bounds for a scan.
type ScanConfig struct {
	MaxPages              int           `json:"max_pages"`
	MaxDepth              int           `json:"max_depth"`
	MaxConcurrency        int           `json:"max_concurrency"`
	RequestTimeoutSeconds int           `json:"request_timeout_seconds"`
	UserAgent             string        `json:"user_agent"`
	FollowRedirects       bool          `json:"follow_redirects"`
	MaxRedirects          int           `json:"max_redirects"`
	RetentionDays         int           `json:"retention_days"`
	MaxReports            int           `json:"max_reports"`
	Timeout               time.Duration `json:"-"`
}

// DefaultScanConfig returns safe default configuration.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		MaxPages:              50,
		MaxDepth:              3,
		MaxConcurrency:        5,
		RequestTimeoutSeconds: 15,
		UserAgent:             "VortexDNS-WebIntelligence/1.0 (+https://vortexdns.internal)",
		FollowRedirects:       true,
		MaxRedirects:          5,
		RetentionDays:         30,
		MaxReports:            1000,
		Timeout:               15 * time.Second,
	}
}

// Scan holds the root state of an active or completed scan.
type Scan struct {
	ID              string      `json:"id"`
	URL             string      `json:"url"`
	TargetHost      string      `json:"target_host"`
	TargetScheme    string      `json:"target_scheme"`
	TargetPort      int         `json:"target_port"`
	Config          ScanConfig  `json:"config"`
	StartedAt       time.Time   `json:"started_at"`
	EndedAt         *time.Time  `json:"ended_at,omitempty"`
	Status          ScanStatus  `json:"status"`
	Progress        int         `json:"progress"` // 0 - 100
	CurrentStage    string      `json:"current_stage"`
	PagesDiscovered int         `json:"pages_discovered"`
	PagesScanned    int         `json:"pages_scanned"`
	PagesSkipped    int         `json:"pages_skipped"`
	RequestsTotal   int         `json:"requests_total"`
	BytesReceived   int64       `json:"bytes_received"`
	ScanDurationMs  int64       `json:"scan_duration_ms"`
	Error           string      `json:"error,omitempty"`
	Report          *ScanReport `json:"report,omitempty"`
}

// ScanEvent defines real-time SSE telemetry messages.
type ScanEvent struct {
	Event     string      `json:"event"`
	ScanID    string      `json:"scan_id"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// TargetInfo captures normalized endpoint information.
type TargetInfo struct {
	URL        string   `json:"url"`
	Scheme     string   `json:"scheme"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	ResolvedIP []string `json:"resolved_ips"`
	Canonical  string   `json:"canonical_url"`
}

// LighthouseResult holds Lighthouse quality measurements.
type LighthouseResult struct {
	Status        string            `json:"status"` // "available", "unavailable", "fallback_heuristics"
	Engine        string            `json:"engine"`
	Performance   *int              `json:"performance,omitempty"`
	Accessibility *int              `json:"accessibility,omitempty"`
	BestPractices *int              `json:"best_practices,omitempty"`
	SEO           *int              `json:"seo,omitempty"`
	PWA           *int              `json:"pwa,omitempty"`
	Metrics       LighthouseMetrics `json:"metrics"`
}

// LighthouseMetrics captures Core Web Vitals and timing metrics.
type LighthouseMetrics struct {
	FCPMs        *float64 `json:"fcp_ms,omitempty"`
	LCPMs        *float64 `json:"lcp_ms,omitempty"`
	TBTMs        *float64 `json:"tbt_ms,omitempty"`
	CLS          *float64 `json:"cls,omitempty"`
	SpeedIndexMs *float64 `json:"speed_index_ms,omitempty"`
	TTIMs        *float64 `json:"tti_ms,omitempty"`
	INPMs        *float64 `json:"inp_ms,omitempty"`
}

// CertChainEntry represents a certificate in the TLS certificate chain.
type CertChainEntry struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	IsCA       bool      `json:"is_ca"`
}

// TLSCheck provides explainable evaluation for a single TLS property.
type TLSCheck struct {
	Check          string   `json:"check"`
	Observed       string   `json:"observed"`
	Expected       string   `json:"expected"`
	Severity       Severity `json:"severity"`
	Evidence       string   `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

// TLSResult contains comprehensive TLS and certificate analysis.
type TLSResult struct {
	Subject             string           `json:"subject"`
	Issuer              string           `json:"issuer"`
	SerialNumber        string           `json:"serial_number"`
	ValidFrom           time.Time        `json:"valid_from"`
	ValidUntil          time.Time        `json:"valid_until"`
	DaysUntilExpiration int              `json:"days_until_expiration"`
	SANs                []string         `json:"sans"`
	CertChain           []CertChainEntry `json:"cert_chain"`
	SignatureAlgorithm  string           `json:"signature_algorithm"`
	PublicKeyAlgorithm  string           `json:"public_key_algorithm"`
	PublicKeySize       int              `json:"public_key_size"`
	TLSVersion          string           `json:"tls_version"`
	ALPN                []string         `json:"alpn"`
	CipherSuite         string           `json:"cipher_suite"`
	OCSPStapling        string           `json:"ocsp_stapling"`
	SNIBehavior         string           `json:"sni_behavior"`
	Checks              []TLSCheck       `json:"checks"`
	Score               int              `json:"score"` // 0 - 100
	Summary             string           `json:"summary"`
}

// RedirectHop represents a single redirect in the chain.
type RedirectHop struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	StatusCode int    `json:"status_code"`
}

// HeaderAnalysis inspects a specific HTTP header.
type HeaderAnalysis struct {
	Header         string   `json:"header"`
	Present        bool     `json:"present"`
	Value          string   `json:"value"`
	Severity       Severity `json:"severity"`
	Issue          string   `json:"issue"`
	Recommendation string   `json:"recommendation"`
}

// CookieAnalysis evaluates public cookie attributes.
type CookieAnalysis struct {
	Name     string   `json:"name"`
	Secure   bool     `json:"secure"`
	HttpOnly bool     `json:"http_only"`
	SameSite string   `json:"same_site"`
	Path     string   `json:"path"`
	Domain   string   `json:"domain"`
	Issues   []string `json:"issues"`
}

// CORSAnalysis inspects public CORS configuration.
type CORSAnalysis struct {
	AllowOrigin              string `json:"allow_origin"`
	AllowCredentials         bool   `json:"allow_credentials"`
	ExposedHeaders           string `json:"exposed_headers"`
	OriginReflected          bool   `json:"origin_reflected"`
	WildcardWithCredentials  bool   `json:"wildcard_with_credentials"`
	PreflightMaxAge          string `json:"preflight_max_age"`
	RiskDescription          string `json:"risk_description"`
}

// HTTPResult aggregates HTTP protocol, headers, cookies, and CORS analysis.
type HTTPResult struct {
	NegotiatedProtocol string                    `json:"negotiated_protocol"`
	SupportedProtocols []string                  `json:"supported_protocols"`
	ALPN               []string                  `json:"alpn"`
	AltSvc             string                    `json:"alt_svc"`
	ResponseProtocol   string                    `json:"response_protocol"`
	Redirects          []RedirectHop             `json:"redirects"`
	Compression        string                    `json:"compression"`
	ContentEncoding    string                    `json:"content_encoding"`
	SecurityHeaders    map[string]HeaderAnalysis `json:"security_headers"`
	Cookies            []CookieAnalysis          `json:"cookies"`
	CORS               CORSAnalysis              `json:"cors"`
}

// TechnologyFinding documents a detected technology with evidence.
type TechnologyFinding struct {
	Technology string   `json:"technology"`
	Category   string   `json:"category"`
	Confidence float64  `json:"confidence"` // 0.00 - 1.00
	Evidence   []string `json:"evidence"`
	Version    string   `json:"version,omitempty"`
	Website    string   `json:"website,omitempty"`
}

// AIFinding captures evidence of AI-native capabilities.
type AIFinding struct {
	Provider   string   `json:"provider"`
	Technology string   `json:"technology"`
	Capability string   `json:"capability"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Exposure   string   `json:"exposure"`
	Risk       string   `json:"risk"`
}

// SecretFinding documents a detected secret (strictly redacted).
type SecretFinding struct {
	SecretType    string   `json:"secret_type"`
	Location      string   `json:"location"`
	RedactedValue string   `json:"redacted_value"`
	Severity      Severity `json:"severity"`
	Confidence    float64  `json:"confidence"`
}

// RemediationDetail provides concrete, actionable remediation steps.
type RemediationDetail struct {
	Action                 string `json:"action"`
	TechnicalFix           string `json:"technical_fix"`
	ExpectedResult         string `json:"expected_result"`
	Verification           string `json:"verification"`
	ImplementationExample string `json:"implementation_example,omitempty"`
}

// SecurityFinding describes an identified risk or misconfiguration.
type SecurityFinding struct {
	ID             string                 `json:"id"`
	Category       string                 `json:"category"`
	Severity       Severity               `json:"severity"`
	Confidence     float64                `json:"confidence"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Evidence       map[string]interface{} `json:"evidence"`
	Impact         string                 `json:"impact"`
	Likelihood     string                 `json:"likelihood"`
	AffectedAsset  string                 `json:"affected_asset"`
	Mitigation     RemediationDetail      `json:"mitigation"`
	Effort         string                 `json:"effort"`   // "Small", "Medium", "Large"
	Priority       string                 `json:"priority"` // "P0", "P1", "P2", "P3"
	MitigationTime string                 `json:"mitigation_time"` // "Immediate", "Short-term", "Medium-term", "Strategic"
}

// PerformanceFinding describes a performance bottleneck or latency issue.
type PerformanceFinding struct {
	ID             string   `json:"id"`
	Metric         string   `json:"metric"`
	ObservedValue  string   `json:"observed_value"`
	Threshold      string   `json:"threshold"`
	Severity       Severity `json:"severity"`
	Impact         string   `json:"impact"`
	Recommendation string   `json:"recommendation"`
}

// PWAFinding evaluates Progressive Web App capabilities.
type PWAFinding struct {
	HasManifest       bool     `json:"has_manifest"`
	ManifestURL       string   `json:"manifest_url,omitempty"`
	Name              string   `json:"name,omitempty"`
	ShortName         string   `json:"short_name,omitempty"`
	DisplayMode       string   `json:"display_mode,omitempty"`
	StartURL          string   `json:"start_url,omitempty"`
	ThemeColor        string   `json:"theme_color,omitempty"`
	BackgroundColor   string   `json:"background_color,omitempty"`
	IconsCount        int      `json:"icons_count"`
	HasServiceWorker  bool     `json:"has_service_worker"`
	ServiceWorkerURL  string   `json:"service_worker_url,omitempty"`
	OfflineReady      bool     `json:"offline_ready"`
	Installable       bool     `json:"installable"`
	Findings          []string `json:"findings"`
}

// NetworkRequest records metadata for an individual HTTP request during scan.
type NetworkRequest struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Host         string `json:"host"`
	Method       string `json:"method"`
	ResourceType string `json:"resource_type"` // document, script, style, image, font, xhr, fetch, other
	Status       int    `json:"status"`
	Protocol     string `json:"protocol"`
	DurationMs   int64  `json:"duration_ms"`
	EncodedSize  int64  `json:"encoded_size"`
	DecodedSize  int64  `json:"decoded_size"`
	CacheStatus  string `json:"cache_status"`
	IsThirdParty bool   `json:"is_third_party"`
	Category     string `json:"category"`
	Initiator    string `json:"initiator,omitempty"`
}

// RouteNode represents a component node in the Route Graph.
type RouteNode struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Category     string `json:"category"` // Target, CDN, Static Asset, API, Auth, Analytics, AI, External Service
	IsThirdParty bool   `json:"is_third_party"`
	Protocol     string `json:"protocol"`
	RequestCount int    `json:"request_count"`
	LatencyMs    int64  `json:"latency_ms"`
	DataSize     int64  `json:"data_size"`
	Status       string `json:"status"`
}

// RouteEdge represents a connection between two Route Nodes.
type RouteEdge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Protocol     string `json:"protocol"`
	RequestCount int    `json:"request_count"`
}

// RouteGraph encapsulates the complete network architecture map.
type RouteGraph struct {
	Nodes []RouteNode `json:"nodes"`
	Edges []RouteEdge `json:"edges"`
}

// ThirdPartyDependency summarizes an identified third-party domain.
type ThirdPartyDependency struct {
	Domain       string `json:"domain"`
	Category     string `json:"category"`
	RequestCount int    `json:"request_count"`
	TotalBytes   int64  `json:"total_bytes"`
	AvgLatencyMs int64  `json:"avg_latency_ms"`
	FailedCount  int    `json:"failed_count"`
	PrivacyRisk  string `json:"privacy_risk"`
}

// WaterfallEntry summarizes waterfall timing for key requests.
type WaterfallEntry struct {
	URL        string `json:"url"`
	DNSMs      int64  `json:"dns_ms"`
	TCPMs      int64  `json:"tcp_ms"`
	TLSMs      int64  `json:"tls_ms"`
	TTFBMs     int64  `json:"ttfb_ms"`
	DownloadMs int64  `json:"download_ms"`
	TotalMs    int64  `json:"total_ms"`
}

// NetworkReport packages request and dependency metrics.
type NetworkReport struct {
	TotalRequests      int                    `json:"total_requests"`
	TotalBytes         int64                  `json:"total_bytes"`
	FirstPartyRequests int                    `json:"first_party_requests"`
	ThirdPartyRequests int                    `json:"third_party_requests"`
	FirstPartyBytes    int64                  `json:"first_party_bytes"`
	ThirdPartyBytes    int64                  `json:"third_party_bytes"`
	Categories         map[string]int         `json:"categories"`
	Dependencies       []ThirdPartyDependency `json:"dependencies"`
	Waterfall          []WaterfallEntry       `json:"waterfall"`
	Requests           []NetworkRequest       `json:"requests"`
}

// AIReport packages AI-native findings, risks, and observability status.
type AIReport struct {
	Classification   string            `json:"classification"` // e.g. "AI-native architecture indicators", "No public AI evidence detected"
	Confidence       float64           `json:"confidence"`
	Findings         []AIFinding       `json:"findings"`
	SecurityFindings []SecurityFinding `json:"security_findings"`
	Secrets          []SecretFinding   `json:"secrets"`
	Observability    map[string]string `json:"observability"`
}

// MitigationGroup groups recommendations by action timeframe.
type MitigationGroup struct {
	Timeframe string            `json:"timeframe"` // "Immediate", "Short-term", "Medium-term", "Strategic"
	Items     []SecurityFinding `json:"items"`
}

// ReportSummary provides the high-level executive briefing.
type ReportSummary struct {
	WebsiteHealth            string `json:"website_health"`
	PerformanceCondition     string `json:"performance_condition"`
	TLSPosture               string `json:"tls_posture"`
	SecurityPosture          string `json:"security_posture"`
	TechStackCount           int    `json:"tech_stack_count"`
	AINativeStatus           string `json:"ai_native_status"`
	AIConfidence             float64 `json:"ai_confidence"`
	CriticalCount            int    `json:"critical_count"`
	HighCount                int    `json:"high_count"`
	MediumCount              int    `json:"medium_count"`
	LowCount                 int    `json:"low_count"`
	InfoCount                int    `json:"info_count"`
	ImmediateMitigationCount int    `json:"immediate_mitigation_count"`
}

// ScanReport is the unified top-level report structure.
type ScanReport struct {
	SchemaVersion     string               `json:"schema_version"`
	ReportVersion     string               `json:"report_version"`
	ScannerVersion    string               `json:"scanner_version"`
	GeneratedAt       time.Time            `json:"generated_at"`
	ReportHash        string               `json:"report_hash"`
	ScanID            string               `json:"scan_id"`
	Target            TargetInfo           `json:"target"`
	ScanConfig        ScanConfig           `json:"scan_config"`
	Summary           ReportSummary        `json:"summary"`
	Lighthouse        *LighthouseResult    `json:"lighthouse"`
	TLS               *TLSResult           `json:"tls"`
	HTTP              *HTTPResult          `json:"http"`
	Security          []SecurityFinding    `json:"security"`
	Technologies      []TechnologyFinding  `json:"technologies"`
	AI                AIReport             `json:"ai"`
	Network           NetworkReport        `json:"network"`
	Routes            RouteGraph           `json:"routes"`
	PWA               *PWAFinding          `json:"pwa"`
	Performance       []PerformanceFinding `json:"performance"`
	Mitigations       []MitigationGroup    `json:"mitigations"`
	TechnicalEvidence map[string]interface{}`json:"technical_evidence"`
	Methodology       string               `json:"methodology"`
	Limitations       []string             `json:"limitations"`
}

// ToJSON serializes the ScanReport into indented JSON.
func (r *ScanReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
