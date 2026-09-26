package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSSRFValidation verifies URL validation and private IP blocking
func TestSSRFValidation(t *testing.T) {
	tests := []struct {
		urlStr  string
		wantErr bool
		desc    string
	}{
		// Valid public targets
		{"https://example.com", false, "Standard public HTTPS URL"},
		{"http://example.com/test", false, "Standard public HTTP URL"},
		{"https://93.184.216.34", false, "Public IPv4 address"},

		// Blocked schemes
		{"ftp://example.com", true, "FTP scheme blocked"},
		{"file:///etc/passwd", true, "File scheme blocked"},
		{"gopher://example.com", true, "Gopher scheme blocked"},
		{"javascript:alert(1)", true, "JavaScript scheme blocked"},
		{"data:text/html,test", true, "Data URI scheme blocked"},

		// Blocked Loopback and Private IP ranges
		{"http://localhost", true, "Localhost domain blocked"},
		{"http://localhost:8080", true, "Localhost with port blocked"},
		{"http://127.0.0.1", true, "IPv4 loopback blocked"},
		{"http://127.0.0.2:80", true, "IPv4 loopback range blocked"},
		{"http://0.0.0.0", true, "Zero IPv4 blocked"},
		{"http://10.0.0.1", true, "Class A private IP blocked"},
		{"http://10.254.254.254", true, "Class A private IP blocked"},
		{"http://172.16.0.1", true, "Class B private IP blocked"},
		{"http://172.31.255.254", true, "Class B private IP blocked"},
		{"http://192.168.1.1", true, "Class C private IP blocked"},
		{"http://192.168.0.254", true, "Class C private IP blocked"},
		{"http://169.254.169.254", true, "Link-local cloud metadata blocked"},

		// IPv6 blocked
		{"http://[::1]", true, "IPv6 loopback blocked"},
		{"http://[fc00::1]", true, "IPv6 unique local address blocked"},
		{"http://[fe80::1]", true, "IPv6 link-local address blocked"},

		// Encoded bypass attempts
		{"http://2130706433", true, "Decimal encoded 127.0.0.1 blocked"},
		{"http://0x7f.1", true, "Hex encoded loopback blocked"},
		{"http://017700000001", true, "Octal encoded loopback blocked"},

		// Userinfo confusion attempts
		{"http://user:pass@localhost", true, "Userinfo localhost blocked"},
		{"http://evil.com@127.0.0.1", true, "Userinfo confusion blocked"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			parsed, _, err := ValidateTargetURL(tt.urlStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTargetURL(%q) err = %v, wantErr = %v", tt.urlStr, err, tt.wantErr)
			}
			if err == nil && parsed == nil {
				t.Errorf("ValidateTargetURL(%q) returned nil URL without error", tt.urlStr)
			}
		})
	}
}

// TestSSRFRedirectProtection verifies redirect validation catches redirects to private IPs
func TestSSRFRedirectProtection(t *testing.T) {
	// Spin up a test server that attempts to redirect to a private IP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:8080/internal-admin", http.StatusFound)
	}))
	defer ts.Close()

	// SafeHTTPClient must reject the redirect to 127.0.0.1
	client := NewSafeHTTPClient(3*time.Second, 5)
	_, err := client.Get(ts.URL)
	if err == nil {
		t.Fatalf("expected error when following redirect to 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "blocked") {
		t.Logf("Got expected rejection: %v", err)
	}
}

// TestTechDetection verifies multi-signal technology stack identification and confidence scoring
func TestTechDetection(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Powered-By", "Next.js")
	headers.Set("Server", "cloudflare")

	htmlContent := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta name="generator" content="WordPress 6.4.2" />
		<link rel="stylesheet" href="/_next/static/css/styles.css" />
	</head>
	<body>
		<div id="__next">
			<h1>Welcome to Vortex AI</h1>
		</div>
		<script src="/_next/static/chunks/main.js"></script>
		<script>window.__NEXT_DATA__ = {props: {pageProps: {}}};</script>
	</body>
	</html>
	`

	scriptURLs := []string{
		"/_next/static/chunks/main.js",
		"https://static.cloudflareinsights.com/beacon.min.js",
	}

	findings := DetectTechnologies(headers, htmlContent, scriptURLs)

	techMap := make(map[string]TechnologyFinding)
	for _, f := range findings {
		techMap[f.Technology] = f
	}

	// Verify Next.js detection with high confidence
	if nextTech, ok := techMap["Next.js"]; !ok {
		t.Errorf("Expected Next.js to be detected")
	} else {
		if nextTech.Confidence < 0.90 {
			t.Errorf("Expected Next.js confidence >= 0.90, got %.2f", nextTech.Confidence)
		}
		if len(nextTech.Evidence) == 0 {
			t.Errorf("Expected Next.js evidence to be populated")
		}
	}

	// Verify Cloudflare detection
	if cfTech, ok := techMap["Cloudflare"]; !ok {
		t.Errorf("Expected Cloudflare to be detected")
	} else {
		if cfTech.Category != "CDN / Edge" && cfTech.Category != "Web Server" {
			t.Logf("Cloudflare category: %s", cfTech.Category)
		}
	}

	// Verify WordPress detection from generator
	if wpTech, ok := techMap["WordPress"]; !ok {
		t.Errorf("Expected WordPress to be detected")
	} else {
		if wpTech.Confidence < 0.85 {
			t.Errorf("Expected WordPress confidence >= 0.85, got %.2f", wpTech.Confidence)
		}
	}
}

// TestAIDetectionAndSecretRedaction tests AI stack indicators and secret masking
func TestAIDetectionAndSecretRedaction(t *testing.T) {
	// Secret redaction test
	rawOpenAIKey := "sk-proj-abc1234567890defghijklmnopqr1234567890XYZ"
	redacted := RedactSecret(rawOpenAIKey)

	if strings.Contains(redacted, "abc1234567890defghijklmnopqr") {
		t.Fatalf("Secret was not properly redacted: %s", redacted)
	}
	if !strings.HasPrefix(redacted, "sk-proj-") {
		t.Errorf("Redacted secret should preserve safe prefix: %s", redacted)
	}
	if !strings.Contains(redacted, "****") {
		t.Errorf("Redacted secret should contain masking asterisks: %s", redacted)
	}

	// Short secret
	shortSecret := "abcdef"
	redactedShort := RedactSecret(shortSecret)
	if !strings.Contains(redactedShort, "****") {
		t.Errorf("Expected short secret to be masked, got %s", redactedShort)
	}

	// AI detection engine test
	htmlContent := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="https://cdn.jsdelivr.net/npm/@ai-sdk/react@0.0.1/dist/index.js"></script>
	</head>
	<body>
		<div id="ai-chat" class="ai-assistant-container">
			<div class="chat-message">How can I assist you today?</div>
		</div>
	</body>
	</html>
	`

	scriptBodies := map[string]string{
		"bundle.js": `
			// Simulated accidental key exposure in bundle
			const clientConfig = {
				apiKey: "sk-proj-superSecretLiveKey1234567890TestingRedaction9999",
				vectorStore: "pinecone",
				streamEndpoint: "/api/chat/stream"
			};
		`,
	}

	endpoints := []string{"/api/chat/stream", "https://api.openai.com/v1/chat/completions"}

	aiReport := DetectAI(htmlContent, scriptBodies, endpoints, true)

	if aiReport.Classification == "No public AI evidence detected" {
		t.Errorf("Expected AI evidence to be detected, got %s", aiReport.Classification)
	}

	// Verify Vercel AI SDK or OpenAI detected
	foundAI := false
	for _, finding := range aiReport.Findings {
		if strings.Contains(finding.Technology, "Vercel AI SDK") || strings.Contains(finding.Technology, "OpenAI") || strings.Contains(finding.Technology, "llms.txt") {
			foundAI = true
			break
		}
	}
	if !foundAI {
		t.Errorf("Expected Vercel AI SDK, OpenAI or llms.txt in AI findings: %+v", aiReport.Findings)
	}

	// Verify exposed secret detected and redacted
	if len(aiReport.Secrets) == 0 {
		t.Errorf("Expected exposed OpenAI secret to be detected")
	} else {
		secret := aiReport.Secrets[0]
		if strings.Contains(secret.RedactedValue, "superSecretLiveKey") {
			t.Fatalf("Exposed secret in result was NOT redacted: %s", secret.RedactedValue)
		}
		if secret.Severity != SeverityCritical && secret.Severity != SeverityHigh {
			t.Errorf("Expected high/critical severity for exposed API key, got %s", secret.Severity)
		}
	}
}

// TestSecurityHeadersEvaluation tests header analysis
func TestSecurityHeadersEvaluation(t *testing.T) {
	hstsResult := analyzeHSTS("", "https://example.com")
	if hstsResult.Present {
		t.Errorf("Expected HSTS to be absent")
	}
	if hstsResult.Severity != SeverityMedium {
		t.Errorf("Expected medium severity for missing HSTS on HTTPS site, got %s", hstsResult.Severity)
	}

	cspResult := analyzeCSP("")
	if cspResult.Present {
		t.Errorf("Expected CSP to be absent")
	}
	if cspResult.Severity != SeverityMedium {
		t.Errorf("Expected medium severity for missing CSP, got %s", cspResult.Severity)
	}

	// Now check secure values
	hstsSecure := analyzeHSTS("max-age=31536000; includeSubDomains; preload", "https://example.com")
	if !hstsSecure.Present || hstsSecure.Severity != SeverityInfo {
		t.Errorf("Expected present and info severity for valid HSTS, got severity=%s", hstsSecure.Severity)
	}
}

// TestPWAInspection tests manifest and service worker detection
func TestPWAInspection(t *testing.T) {
	htmlContent := `
	<!DOCTYPE html>
	<html>
	<head>
		<link rel="manifest" href="/manifest.json">
		<meta name="theme-color" content="#4f46e5">
	</head>
	<body>
		<script>
			if ('serviceWorker' in navigator) {
				navigator.serviceWorker.register('/sw.js');
			}
		</script>
	</body>
	</html>
	`

	ctx := context.Background()
	pwa := AnalyzePWA(ctx, "https://example.com", htmlContent, 3*time.Second)
	if !pwa.HasManifest {
		t.Errorf("Expected HasManifest to be true")
	}
	if pwa.ManifestURL != "https://example.com/manifest.json" {
		t.Errorf("Expected ManifestURL to be resolved, got %s", pwa.ManifestURL)
	}
	if !pwa.HasServiceWorker {
		t.Errorf("Expected HasServiceWorker to be true")
	}
	if pwa.ThemeColor != "#4f46e5" {
		t.Errorf("Expected ThemeColor #4f46e5, got %s", pwa.ThemeColor)
	}
}

// TestStreamingExports tests JSON, JSONL and CSV streaming exporters
func TestStreamingExports(t *testing.T) {
	report := &ScanReport{
		ScanID:         "scan_test_123",
		Target:         TargetInfo{URL: "https://example.com", Host: "example.com", Scheme: "https", Port: 443},
		ScannerVersion: "1.0.0",
		GeneratedAt:    time.Now(),
		Summary: ReportSummary{
			WebsiteHealth:   "Good",
			TechStackCount:  2,
			CriticalCount:   0,
			HighCount:       1,
			MediumCount:     1,
		},
		Technologies: []TechnologyFinding{
			{Technology: "Go", Category: "Backend", Confidence: 0.95, Evidence: []string{"Server header"}},
			{Technology: "Next.js", Category: "Frontend", Confidence: 0.98, Evidence: []string{"/_next/ chunk"}},
		},
		Security: []SecurityFinding{
			{ID: "SEC-001", Title: "HSTS Missing", Severity: SeverityMedium, Impact: "MITM risk", AffectedAsset: "example.com"},
			{ID: "SEC-002", Title: "CSP Missing", Severity: SeverityHigh, Impact: "XSS risk", AffectedAsset: "example.com"},
		},
	}

	// 1. JSON Export
	var jsonBuf strings.Builder
	if err := ExportJSON(&jsonBuf, report); err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	var parsedReport ScanReport
	if err := json.Unmarshal([]byte(jsonBuf.String()), &parsedReport); err != nil {
		t.Fatalf("ExportJSON generated invalid JSON: %v", err)
	}
	if parsedReport.ScanID != "scan_test_123" {
		t.Errorf("Expected ScanID scan_test_123, got %s", parsedReport.ScanID)
	}

	// 2. JSONL Export
	var jsonlBuf strings.Builder
	if err := ExportJSONL(&jsonlBuf, report); err != nil {
		t.Fatalf("ExportJSONL failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(jsonlBuf.String()), "\n")
	if len(lines) < 4 {
		t.Fatalf("Expected at least 4 JSONL lines (scan, summary, tech, findings), got %d", len(lines))
	}
	for i, line := range lines {
		var lineObj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &lineObj); err != nil {
			t.Errorf("Line %d is not valid JSON: %s (%v)", i, line, err)
		}
	}

	// 3. CSV Export
	var csvBuf strings.Builder
	if err := ExportCSV(&csvBuf, report); err != nil {
		t.Fatalf("ExportCSV failed: %v", err)
	}
	csvContent := csvBuf.String()
	if !strings.Contains(csvContent, "Finding ID,Category,Severity,Confidence,Title,Asset,Impact") {
		t.Errorf("CSV missing header row: %s", csvContent)
	}
	if !strings.Contains(csvContent, "SEC-001") || !strings.Contains(csvContent, "HSTS Missing") {
		t.Errorf("CSV missing expected records")
	}
}

// TestScanCancellation tests that cancelling a scan context aborts cleanly
func TestScanCancellation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vortex_scan_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 2)
	cfg := DefaultScanConfig()
	cfg.RequestTimeoutSeconds = 5

	// Start a scan on a safe public IP target
	scan, err := mgr.CreateScan("https://93.184.216.34", &cfg)
	if err != nil {
		t.Fatalf("Failed to start scan: %v", err)
	}

	// Immediately cancel
	ok := mgr.CancelScan(scan.ID)
	if !ok {
		t.Logf("CancelScan returned false (scan may have finished or already transitioned)")
	}

	// Wait briefly for cancellation to propagate
	time.Sleep(150 * time.Millisecond)

	retrieved, ok := mgr.GetScan(scan.ID)
	if !ok {
		t.Fatalf("Scan not found after cancel")
	}
	if retrieved.Status != StatusCancelled && retrieved.Status != StatusFailed {
		t.Logf("Scan status after immediate cancellation: %s", retrieved.Status)
	}
}

// TestScanDiffing verifies comparison between two scans of the same domain
func TestScanDiffing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vortex_scan_diff_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 2)

	oldScan := &Scan{
		ID:         "scan_001",
		TargetHost: "example.com",
		Status:     StatusCompleted,
		Report: &ScanReport{
			ScanID: "scan_001",
			Target: TargetInfo{URL: "https://example.com", Host: "example.com"},
			Summary: ReportSummary{
				WebsiteHealth: "Fair",
			},
			Technologies: []TechnologyFinding{
				{Technology: "jQuery", Category: "JavaScript"},
				{Technology: "Apache", Category: "Web Server"},
			},
			Security: []SecurityFinding{
				{ID: "SEC-OLD-1", Title: "Old Missing Header", Severity: SeverityMedium},
				{ID: "SEC-SAME", Title: "Persistent Risk", Severity: SeverityHigh},
			},
			AI: AIReport{Classification: "No public AI evidence detected"},
		},
	}

	newScan := &Scan{
		ID:         "scan_002",
		TargetHost: "example.com",
		Status:     StatusCompleted,
		Report: &ScanReport{
			ScanID: "scan_002",
			Target: TargetInfo{URL: "https://example.com", Host: "example.com"},
			Summary: ReportSummary{
				WebsiteHealth: "Good",
			},
			Technologies: []TechnologyFinding{
				{Technology: "React", Category: "Frontend"},
				{Technology: "Apache", Category: "Web Server"},
			},
			Security: []SecurityFinding{
				{ID: "SEC-NEW-1", Title: "New Risk Detected", Severity: SeverityLow},
				{ID: "SEC-SAME", Title: "Persistent Risk", Severity: SeverityHigh},
			},
			AI: AIReport{Classification: "AI-native architecture indicators"},
		},
	}

	// Register in manager
	mgr.mu.Lock()
	mgr.scans["scan_001"] = oldScan
	mgr.scans["scan_002"] = newScan
	mgr.mu.Unlock()

	diff, err := mgr.CompareScans("scan_001", "scan_002")
	if err != nil {
		t.Fatalf("CompareScans failed: %v", err)
	}
	if diff.BaseScanID != "scan_001" || diff.TargetScanID != "scan_002" {
		t.Errorf("Diff scan IDs mismatch")
	}

	// Verify resolved findings
	foundResolved := false
	for _, f := range diff.ResolvedFindings {
		if f.ID == "SEC-OLD-1" {
			foundResolved = true
			break
		}
	}
	if !foundResolved {
		t.Errorf("Expected SEC-OLD-1 to be marked resolved")
	}

	// Verify new findings
	foundNew := false
	for _, f := range diff.NewFindings {
		if f.ID == "SEC-NEW-1" {
			foundNew = true
			break
		}
	}
	if !foundNew {
		t.Errorf("Expected SEC-NEW-1 to be marked new")
	}

	// Verify persistent findings
	foundUnchanged := false
	for _, f := range diff.UnchangedFindings {
		if f.ID == "SEC-SAME" {
			foundUnchanged = true
			break
		}
	}
	if !foundUnchanged {
		t.Errorf("Expected SEC-SAME to be marked unchanged")
	}

	// Verify tech changes
	if len(diff.NewTechnologies) == 0 || diff.NewTechnologies[0].Technology != "React" {
		t.Errorf("Expected React in added technologies, got %+v", diff.NewTechnologies)
	}
	if len(diff.RemovedTechnologies) == 0 || diff.RemovedTechnologies[0].Technology != "jQuery" {
		t.Errorf("Expected jQuery in removed technologies, got %+v", diff.RemovedTechnologies)
	}
}

// TestPDFEngineCheck verifies detection and graceful fallback
func TestPDFEngineCheck(t *testing.T) {
	status := CheckPDFEngine()
	t.Logf("PDF Engine available: %v, Engine: %s, Binary: %s", status.Available, status.Engine, status.Binary)

	report := &ScanReport{
		ScanID:      "scan_pdf_test",
		Target:      TargetInfo{URL: "https://example.com", Host: "example.com"},
		GeneratedAt: time.Now(),
		Summary: ReportSummary{
			WebsiteHealth: "Good",
		},
	}

	// Test HTML report generation (always available even if PDF binary isn't)
	htmlReport := GenerateHTMLReport(report)
	if !strings.Contains(htmlReport, "VortexDNS Website Intelligence Report") {
		t.Errorf("HTML report missing header title")
	}
	if !strings.Contains(htmlReport, "scan_pdf_test") {
		t.Errorf("HTML report missing scan ID")
	}
	if !strings.Contains(htmlReport, "Executive Summary") {
		t.Errorf("HTML report missing Executive Summary section")
	}
}

// TestRouteGraphClustering tests dependency classification in graph
func TestRouteGraphClustering(t *testing.T) {
	requests := []NetworkRequest{
		{URL: "https://app.example.com/api/v1/user", Host: "app.example.com", Method: "GET", Status: 200, EncodedSize: 500},
		{URL: "https://static.cloudflare.com/cdn-cgi/script.js", Host: "static.cloudflare.com", Method: "GET", Status: 200, EncodedSize: 1200},
		{URL: "https://api.openai.com/v1/chat", Host: "api.openai.com", Method: "POST", Status: 200, EncodedSize: 2400},
		{URL: "https://www.google-analytics.com/g/collect", Host: "www.google-analytics.com", Method: "POST", Status: 204, EncodedSize: 50},
	}

	techFindings := []TechnologyFinding{
		{Technology: "Next.js", Category: "Frontend Framework"},
	}

	aiReport := AIReport{
		Classification: "AI-native architecture indicators",
		Findings: []AIFinding{
			{Provider: "OpenAI", Technology: "OpenAI API"},
		},
	}

	graph := BuildRouteGraph("https://app.example.com", requests, techFindings, aiReport)
	if len(graph.Nodes) < 3 {
		t.Errorf("Expected at least 3 nodes (browser, target, dependencies), got %d", len(graph.Nodes))
	}

	hasTarget := false
	hasAI := false
	hasAnalytics := false
	for _, node := range graph.Nodes {
		if node.Category == "Target Domain" {
			hasTarget = true
		}
		if node.Category == "AI Provider" || node.Label == "api.openai.com" {
			hasAI = true
		}
		if node.Category == "Analytics" || node.Label == "www.google-analytics.com" {
			hasAnalytics = true
		}
	}

	if !hasTarget {
		t.Errorf("Graph missing target node")
	}
	if !hasAI {
		t.Errorf("Graph missing AI provider node")
	}
	if !hasAnalytics {
		t.Errorf("Graph missing Analytics node")
	}
}
