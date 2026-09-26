package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanDiff represents comparative differences between two scans of the same host.
type ScanDiff struct {
	BaseScanID       string              `json:"base_scan_id"`
	TargetScanID     string              `json:"target_scan_id"`
	Host             string              `json:"host"`
	NewFindings      []SecurityFinding   `json:"new_findings"`
	ResolvedFindings []SecurityFinding   `json:"resolved_findings"`
	UnchangedFindings []SecurityFinding  `json:"unchanged_findings"`
	NewTechnologies  []TechnologyFinding `json:"new_technologies"`
	RemovedTechnologies []TechnologyFinding `json:"removed_technologies"`
	TLSChanges       map[string]string   `json:"tls_changes"`
	AISummaryChange  string              `json:"ai_summary_change"`
}

// ScanManager coordinates scanning jobs, event broadcast channels, and persistence.
type ScanManager struct {
	mu           sync.RWMutex
	scans        map[string]*Scan
	cancelFuncs  map[string]context.CancelFunc
	eventBuffers map[string][]ScanEvent // bounded circular buffer per scan
	subscribers  map[string][]chan ScanEvent
	subMu        sync.Mutex
	semaphore    chan struct{} // limits concurrent scans
	dbDir        string
	reportsDir   string
}

// NewManager initializes the ScanManager.
func NewManager(dbDir string, maxConcurrentScans int) *ScanManager {
	if dbDir == "" {
		dbDir = "vortex_db"
	}
	scansDir := filepath.Join(dbDir, "scans")
	reportsDir := filepath.Join(dbDir, "reports")
	_ = os.MkdirAll(scansDir, 0755)
	_ = os.MkdirAll(reportsDir, 0755)

	if maxConcurrentScans <= 0 {
		maxConcurrentScans = 2
	}

	mgr := &ScanManager{
		scans:        make(map[string]*Scan),
		cancelFuncs:  make(map[string]context.CancelFunc),
		eventBuffers: make(map[string][]ScanEvent),
		subscribers:  make(map[string][]chan ScanEvent),
		semaphore:    make(chan struct{}, maxConcurrentScans),
		dbDir:        scansDir,
		reportsDir:   reportsDir,
	}

	mgr.loadHistoricalScans()
	return mgr
}

func generateScanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "scan_" + hex.EncodeToString(b)
}

// CreateScan initializes and queues a new website scan.
func (m *ScanManager) CreateScan(rawURL string, cfg *ScanConfig) (*Scan, error) {
	parsedURL, resolvedIPs, err := ValidateTargetURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}

	var scanCfg ScanConfig
	if cfg != nil {
		scanCfg = *cfg
	} else {
		scanCfg = DefaultScanConfig()
	}
	if scanCfg.MaxPages <= 0 {
		scanCfg.MaxPages = 50
	}
	if scanCfg.MaxDepth <= 0 {
		scanCfg.MaxDepth = 3
	}
	if scanCfg.MaxConcurrency <= 0 {
		scanCfg.MaxConcurrency = 5
	}
	if scanCfg.RequestTimeoutSeconds <= 0 {
		scanCfg.RequestTimeoutSeconds = 15
	}
	if scanCfg.UserAgent == "" {
		scanCfg.UserAgent = DefaultScanConfig().UserAgent
	}
	if scanCfg.RetentionDays <= 0 {
		scanCfg.RetentionDays = 30
	}
	if scanCfg.MaxReports <= 0 {
		scanCfg.MaxReports = 1000
	}

	port := 80
	if parsedURL.Scheme == "https" {
		port = 443
	}
	if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}

	scanID := generateScanID()
	scan := &Scan{
		ID:           scanID,
		URL:          parsedURL.String(),
		TargetHost:   parsedURL.Host,
		TargetScheme: parsedURL.Scheme,
		TargetPort:   port,
		Config:       scanCfg,
		StartedAt:    time.Now().UTC(),
		Status:       StatusQueued,
		Progress:     0,
		CurrentStage: "Queued",
	}

	m.mu.Lock()
	m.scans[scanID] = scan
	m.eventBuffers[scanID] = make([]ScanEvent, 0, 500)
	m.mu.Unlock()

	IncScanTotal()

	// Launch scan in worker goroutine
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancelFuncs[scanID] = cancel
	m.mu.Unlock()

	go m.runScanPipeline(ctx, scan, parsedURL, resolvedIPs)

	return scan, nil
}

// runScanPipeline executes the stages of the scan under bounded concurrency.
func (m *ScanManager) runScanPipeline(ctx context.Context, scan *Scan, targetURL *url.URL, resolvedIPs []net.IP) {
	// Acquire concurrency semaphore
	select {
	case m.semaphore <- struct{}{}:
		defer func() { <-m.semaphore }()
	case <-ctx.Done():
		m.markCancelled(scan)
		return
	}

	IncScanActive()
	defer DecScanActive()

	startTime := time.Now()
	scanID := scan.ID
	targetHost := targetURL.Host

	m.updateStage(scan, StatusRunning, 5, "Connecting & validating DNS/SSRF")
	m.publishEvent(scanID, "scan.started", map[string]interface{}{
		"target": targetURL.String(),
		"host":   targetHost,
	})

	ips := make([]string, 0, len(resolvedIPs))
	for _, ip := range resolvedIPs {
		ips = append(ips, ip.String())
	}

	targetInfo := TargetInfo{
		URL:        targetURL.String(),
		Scheme:     targetURL.Scheme,
		Host:       targetHost,
		Port:       scan.TargetPort,
		ResolvedIP: ips,
		Canonical:  targetURL.String(),
	}

	m.publishEvent(scanID, "dns.completed", map[string]interface{}{
		"ips": ips,
	})

	// ── STAGE 1: TLS & Certificate Analysis ──
	var tlsResult *TLSResult
	if targetURL.Scheme == "https" {
		m.updateStage(scan, StatusRunning, 15, "Inspecting TLS certificates and cipher suites")
		_, span := StartSpan(ctx, "scan.tls", scanID, targetHost)
		res, err := AnalyzeTLS(targetHost, scan.TargetPort, 10*time.Second)
		span.End()
		if err == nil {
			tlsResult = res
			m.publishEvent(scanID, "tls.completed", map[string]interface{}{
				"score":       res.Score,
				"tls_version": res.TLSVersion,
				"expiry_days": res.DaysUntilExpiration,
			})
		}
	}

	if ctx.Err() != nil {
		m.markCancelled(scan)
		return
	}

	// ── STAGE 2: HTTP Protocols & Security Headers ──
	m.updateStage(scan, StatusRunning, 25, "Analyzing HTTP protocols, security headers, and CORS")
	_, spanHTTP := StartSpan(ctx, "scan.http", scanID, targetHost)
	httpResult, resp, _, err := AnalyzeHTTP(ctx, targetURL.String(), time.Duration(scan.Config.RequestTimeoutSeconds)*time.Second)
	spanHTTP.End()

	var initialHTML string
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err == nil && httpResult != nil {
		m.publishEvent(scanID, "http.completed", map[string]interface{}{
			"protocol":  httpResult.NegotiatedProtocol,
			"protocols": httpResult.SupportedProtocols,
			"alt_svc":   httpResult.AltSvc,
		})
	}

	if ctx.Err() != nil {
		m.markCancelled(scan)
		return
	}

	// ── STAGE 3: Bounded Crawling ──
	m.updateStage(scan, StatusRunning, 40, "Crawling page structure and discovering assets")
	crawler := NewBoundedCrawler(scan.Config, targetURL)
	crawlResult, _ := crawler.Crawl(ctx, func(discovered, scanned, skipped int, stage string) {
		m.mu.Lock()
		scan.PagesDiscovered = discovered
		scan.PagesScanned = scanned
		scan.PagesSkipped = skipped
		m.mu.Unlock()
		m.publishEvent(scanID, "scan.progress", map[string]interface{}{
			"pages_discovered": discovered,
			"pages_scanned":    scanned,
			"pages_skipped":    skipped,
		})
	})

	if crawlResult != nil {
		scan.PagesDiscovered = crawlResult.PagesDiscovered
		scan.PagesScanned = crawlResult.PagesScanned
		scan.PagesSkipped = crawlResult.PagesSkipped
		scan.RequestsTotal = crawlResult.RequestsTotal
		scan.BytesReceived = crawlResult.BytesReceived

		AddScanPages(int64(crawlResult.PagesScanned))
		AddScanRequests(int64(crawlResult.RequestsTotal))
		AddScanBytes(crawlResult.BytesReceived)

		if initialContent, ok := crawlResult.HTMLBodies[targetURL.String()]; ok {
			initialHTML = initialContent
		}
	}

	if ctx.Err() != nil {
		m.markCancelled(scan)
		return
	}

	// ── STAGE 4: Technology Stack Detection ──
	m.updateStage(scan, StatusRunning, 60, "Detecting technology stack & frameworks")
	var headers http.Header
	if resp != nil {
		headers = resp.Header
	} else {
		headers = make(http.Header)
	}

	var scriptURLs []string
	var scriptBodies map[string]string
	var endpoints []string
	hasLLMSTxt := false
	if crawlResult != nil {
		scriptURLs = crawlResult.ScriptURLs
		scriptBodies = crawlResult.ScriptBodies
		endpoints = crawlResult.Endpoints
		hasLLMSTxt = crawlResult.HasLLMSTxt
	}

	techFindings := DetectTechnologies(headers, initialHTML, scriptURLs)
	for _, tf := range techFindings {
		m.publishEvent(scanID, "technology.detected", tf)
	}

	// ── STAGE 5: AI-Native Detection & Secret Scanning ──
	m.updateStage(scan, StatusRunning, 75, "Performing AI-native capability inspection & secret audit")
	aiReport := DetectAI(initialHTML, scriptBodies, endpoints, hasLLMSTxt)
	for _, af := range aiReport.Findings {
		m.publishEvent(scanID, "ai.detected", af)
	}

	// ── STAGE 6: PWA Analysis ──
	m.updateStage(scan, StatusRunning, 85, "Inspecting Progressive Web App signals")
	pwaResult := AnalyzePWA(ctx, targetURL.String(), initialHTML, 5*time.Second)

	// ── STAGE 7: Lighthouse Quality Measurements ──
	m.updateStage(scan, StatusRunning, 90, "Evaluating Lighthouse Core Web Vitals")
	m.publishEvent(scanID, "lighthouse.started", map[string]interface{}{"url": targetURL.String()})
	lhResult := MeasureLighthouse(ctx, targetURL.String(), 20*time.Second)
	m.publishEvent(scanID, "lighthouse.completed", lhResult)

	// ── STAGE 8: Route Graph & Synthesize Findings ──
	m.updateStage(scan, StatusRunning, 95, "Generating Route Graph & Actionable Mitigations")
	var reqs []NetworkRequest
	var waterfall []WaterfallEntry
	if crawlResult != nil {
		reqs = crawlResult.Requests
		waterfall = crawlResult.Waterfall
	}
	routeGraph := BuildRouteGraph(targetURL.String(), reqs, techFindings, aiReport)

	securityFindings, performanceFindings, mitigations, summary := GenerateFindings(
		targetHost,
		tlsResult,
		httpResult,
		aiReport,
		pwaResult,
		crawlResult,
	)

	summary.TechStackCount = len(techFindings)
	AddScanFindings(int64(len(securityFindings) + len(performanceFindings)))

	for _, sf := range securityFindings {
		m.publishEvent(scanID, "security.finding", sf)
	}
	for _, pf := range performanceFindings {
		m.publishEvent(scanID, "performance.finding", pf)
	}

	// Calculate third party stats
	firstReqs := 0
	thirdReqs := 0
	var firstBytes, thirdBytes int64
	catCount := make(map[string]int)

	for _, r := range reqs {
		if r.IsThirdParty {
			thirdReqs++
			thirdBytes += r.EncodedSize
		} else {
			firstReqs++
			firstBytes += r.EncodedSize
		}
		catCount[r.Category]++
	}

	// Third Party Dependencies List
	tpMap := make(map[string]*ThirdPartyDependency)
	for _, r := range reqs {
		if r.IsThirdParty && r.Host != "" {
			dep, ok := tpMap[r.Host]
			if !ok {
				dep = &ThirdPartyDependency{
					Domain:      r.Host,
					Category:    r.Category,
					PrivacyRisk: "Public external resource request observed.",
				}
				tpMap[r.Host] = dep
			}
			dep.RequestCount++
			dep.TotalBytes += r.EncodedSize
			if r.Status >= 400 {
				dep.FailedCount++
			}
		}
	}
	var tpList []ThirdPartyDependency
	for _, dep := range tpMap {
		tpList = append(tpList, *dep)
	}

	networkReport := NetworkReport{
		TotalRequests:      len(reqs),
		TotalBytes:         firstBytes + thirdBytes,
		FirstPartyRequests: firstReqs,
		ThirdPartyRequests: thirdReqs,
		FirstPartyBytes:    firstBytes,
		ThirdPartyBytes:    thirdBytes,
		Categories:         catCount,
		Dependencies:       tpList,
		Waterfall:          waterfall,
		Requests:           reqs,
	}

	// Final ScanReport Object
	now := time.Now().UTC()
	scanDuration := now.Sub(startTime)

	report := &ScanReport{
		SchemaVersion:     SchemaVersion,
		ReportVersion:     ReportVersion,
		ScannerVersion:    ScannerVersion,
		GeneratedAt:       now,
		ScanID:            scanID,
		Target:            targetInfo,
		ScanConfig:        scan.Config,
		Summary:           summary,
		Lighthouse:        lhResult,
		TLS:               tlsResult,
		HTTP:              httpResult,
		Security:          securityFindings,
		Technologies:      techFindings,
		AI:                aiReport,
		Network:           networkReport,
		Routes:            routeGraph,
		PWA:               pwaResult,
		Performance:       performanceFindings,
		Mitigations:       mitigations,
		TechnicalEvidence: map[string]interface{}{},
		Methodology:       "Non-destructive, rate-limited public surface analysis combining RFC-compliant TLS audits, HTTP protocol checks, heuristic fingerprinting, and standard web compliance checks.",
		Limitations: []string{
			"External scanners cannot observe server-side databases, internal private microservices, or private source repositories.",
			"Authenticated user workflows and routes behind login portals are excluded to avoid account lockout or credential misuse.",
			"AI observability (e.g. internal token costs, vector retrieval latency) cannot be measured externally unless public telemetry headers are exposed.",
		},
	}

	report.ReportHash = ComputeReportHash(report)

	// Save Report and Artifacts
	m.saveReport(scanID, report)

	// Generate and cache PDF Report
	pdfPath := filepath.Join(m.reportsDir, fmt.Sprintf("%s.pdf", scanID))
	_ = RenderPDF(context.Background(), report, pdfPath)
	IncScanReports()

	// ── COMPLETE SCAN ──
	m.mu.Lock()
	scan.Status = StatusCompleted
	scan.Progress = 100
	scan.CurrentStage = "Completed"
	scan.EndedAt = &now
	scan.ScanDurationMs = scanDuration.Milliseconds()
	scan.Report = report
	m.mu.Unlock()

	AddScanDuration(int64(scanDuration.Seconds()))
	m.persistScanMeta(scan)
	m.pruneRetention()

	m.publishEvent(scanID, "scan.completed", map[string]interface{}{
		"scan_id":     scanID,
		"duration_ms": scan.ScanDurationMs,
		"report_hash": report.ReportHash,
	})
}

func (m *ScanManager) markCancelled(scan *Scan) {
	now := time.Now().UTC()
	m.mu.Lock()
	scan.Status = StatusCancelled
	scan.CurrentStage = "Cancelled by user"
	scan.EndedAt = &now
	m.mu.Unlock()

	m.publishEvent(scan.ID, "scan.cancelled", map[string]interface{}{
		"scan_id": scan.ID,
	})
	m.persistScanMeta(scan)
}

func (m *ScanManager) updateStage(scan *Scan, status ScanStatus, progress int, stage string) {
	m.mu.Lock()
	scan.Status = status
	scan.Progress = progress
	scan.CurrentStage = stage
	m.mu.Unlock()

	m.publishEvent(scan.ID, "scan.progress", map[string]interface{}{
		"progress": progress,
		"stage":    stage,
	})
}

// CancelScan aborts an active scan.
func (m *ScanManager) CancelScan(scanID string) bool {
	m.mu.Lock()
	cancel, ok := m.cancelFuncs[scanID]
	scan, exists := m.scans[scanID]
	m.mu.Unlock()

	if !ok || !exists || scan.Status == StatusCompleted || scan.Status == StatusCancelled {
		return false
	}

	cancel()
	return true
}

// GetScan retrieves a scan by ID.
func (m *ScanManager) GetScan(scanID string) (*Scan, bool) {
	m.mu.RLock()
	scan, ok := m.scans[scanID]
	m.mu.RUnlock()

	if !ok {
		// Attempt to load from disk
		diskScan, err := m.loadScanMeta(scanID)
		if err == nil && diskScan != nil {
			m.mu.Lock()
			m.scans[scanID] = diskScan
			m.mu.Unlock()
			return diskScan, true
		}
		return nil, false
	}

	return scan, true
}

// ListScans returns paginated historical scans, newest first.
func (m *ScanManager) ListScans(limit, offset int) ([]*Scan, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Scan, 0, len(m.scans))
	for _, s := range m.scans {
		list = append(list, s)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].StartedAt.After(list[j].StartedAt)
	})

	total := len(list)
	if offset >= total {
		return []*Scan{}, total
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return list[offset:end], total
}

// DeleteScan removes scan metadata and generated reports.
func (m *ScanManager) DeleteScan(scanID string) bool {
	m.CancelScan(scanID)

	m.mu.Lock()
	delete(m.scans, scanID)
	delete(m.cancelFuncs, scanID)
	delete(m.eventBuffers, scanID)
	m.mu.Unlock()

	// Remove files
	metaPath := filepath.Join(m.dbDir, fmt.Sprintf("%s.json", scanID))
	_ = os.Remove(metaPath)
	repPath := filepath.Join(m.reportsDir, fmt.Sprintf("%s.json", scanID))
	_ = os.Remove(repPath)
	pdfPath := filepath.Join(m.reportsDir, fmt.Sprintf("%s.pdf", scanID))
	_ = os.Remove(pdfPath)
	htmlPath := filepath.Join(m.reportsDir, fmt.Sprintf("%s.html", scanID))
	_ = os.Remove(htmlPath)

	return true
}

// SubscribeEvents registers a subscriber channel for real-time SSE scan events.
func (m *ScanManager) SubscribeEvents(scanID string) (chan ScanEvent, []ScanEvent, func()) {
	ch := make(chan ScanEvent, 50)

	m.subMu.Lock()
	m.subscribers[scanID] = append(m.subscribers[scanID], ch)
	m.subMu.Unlock()

	m.mu.RLock()
	history := make([]ScanEvent, len(m.eventBuffers[scanID]))
	copy(history, m.eventBuffers[scanID])
	m.mu.RUnlock()

	unsubscribe := func() {
		m.subMu.Lock()
		defer m.subMu.Unlock()
		subs := m.subscribers[scanID]
		for i, sub := range subs {
			if sub == ch {
				m.subscribers[scanID] = append(subs[:i], subs[i+1:]...)
				close(ch)
				break
			}
		}
	}

	return ch, history, unsubscribe
}

func (m *ScanManager) publishEvent(scanID, eventName string, data interface{}) {
	ev := ScanEvent{
		Event:     eventName,
		ScanID:    scanID,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	m.mu.Lock()
	buf := m.eventBuffers[scanID]
	if len(buf) >= 500 {
		buf = buf[1:]
	}
	m.eventBuffers[scanID] = append(buf, ev)
	m.mu.Unlock()

	m.subMu.Lock()
	subs := m.subscribers[scanID]
	for _, sub := range subs {
		select {
		case sub <- ev:
		default:
			// Buffer full, drop event to prevent blocking scanner
		}
	}
	m.subMu.Unlock()
}

func (m *ScanManager) saveReport(scanID string, report *ScanReport) {
	path := filepath.Join(m.reportsDir, fmt.Sprintf("%s.json", scanID))
	data, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0644)
	}
}

func (m *ScanManager) persistScanMeta(scan *Scan) {
	path := filepath.Join(m.dbDir, fmt.Sprintf("%s.json", scan.ID))
	data, err := json.MarshalIndent(scan, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0644)
	}
}

func (m *ScanManager) loadScanMeta(scanID string) (*Scan, error) {
	path := filepath.Join(m.dbDir, fmt.Sprintf("%s.json", scanID))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var scan Scan
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, err
	}

	// Try load full report
	repPath := filepath.Join(m.reportsDir, fmt.Sprintf("%s.json", scanID))
	repData, err := os.ReadFile(repPath)
	if err == nil {
		var rep ScanReport
		if err := json.Unmarshal(repData, &rep); err == nil {
			scan.Report = &rep
		}
	}

	return &scan, nil
}

func (m *ScanManager) loadHistoricalScans() {
	files, err := os.ReadDir(m.dbDir)
	if err != nil {
		return
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			scanID := strings.TrimSuffix(f.Name(), ".json")
			if scan, err := m.loadScanMeta(scanID); err == nil {
				m.scans[scanID] = scan
			}
		}
	}
}

func (m *ScanManager) pruneRetention() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	cutoff := now.Add(-30 * 24 * time.Hour) // default 30 days

	for id, s := range m.scans {
		if s.EndedAt != nil && s.EndedAt.Before(cutoff) {
			delete(m.scans, id)
			_ = os.Remove(filepath.Join(m.dbDir, id+".json"))
			_ = os.Remove(filepath.Join(m.reportsDir, id+".json"))
			_ = os.Remove(filepath.Join(m.reportsDir, id+".pdf"))
			_ = os.Remove(filepath.Join(m.reportsDir, id+".html"))
		}
	}
}

// CompareScans computes diff between an earlier scan and a newer scan of the same domain.
func (m *ScanManager) CompareScans(baseID, targetID string) (*ScanDiff, error) {
	baseScan, ok1 := m.GetScan(baseID)
	targetScan, ok2 := m.GetScan(targetID)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("one or both scans not found")
	}

	if baseScan.Report == nil || targetScan.Report == nil {
		return nil, fmt.Errorf("both scans must be completed to compute diff")
	}

	diff := &ScanDiff{
		BaseScanID:          baseID,
		TargetScanID:        targetID,
		Host:                targetScan.TargetHost,
		NewFindings:         []SecurityFinding{},
		ResolvedFindings:    []SecurityFinding{},
		UnchangedFindings:   []SecurityFinding{},
		NewTechnologies:     []TechnologyFinding{},
		RemovedTechnologies: []TechnologyFinding{},
		TLSChanges:          make(map[string]string),
	}

	// Compare Findings
	baseFindings := make(map[string]SecurityFinding)
	for _, f := range baseScan.Report.Security {
		baseFindings[f.Title] = f
	}

	targetFindings := make(map[string]SecurityFinding)
	for _, f := range targetScan.Report.Security {
		targetFindings[f.Title] = f
		if _, existed := baseFindings[f.Title]; !existed {
			diff.NewFindings = append(diff.NewFindings, f)
		} else {
			diff.UnchangedFindings = append(diff.UnchangedFindings, f)
		}
	}

	for title, f := range baseFindings {
		if _, existsNow := targetFindings[title]; !existsNow {
			diff.ResolvedFindings = append(diff.ResolvedFindings, f)
		}
	}

	// Compare Technologies
	baseTech := make(map[string]TechnologyFinding)
	for _, t := range baseScan.Report.Technologies {
		baseTech[t.Technology] = t
	}
	targetTech := make(map[string]TechnologyFinding)
	for _, t := range targetScan.Report.Technologies {
		targetTech[t.Technology] = t
		if _, existed := baseTech[t.Technology]; !existed {
			diff.NewTechnologies = append(diff.NewTechnologies, t)
		}
	}
	for name, t := range baseTech {
		if _, existsNow := targetTech[name]; !existsNow {
			diff.RemovedTechnologies = append(diff.RemovedTechnologies, t)
		}
	}

	// Compare TLS
	if baseScan.Report.TLS != nil && targetScan.Report.TLS != nil {
		if baseScan.Report.TLS.Score != targetScan.Report.TLS.Score {
			diff.TLSChanges["score"] = fmt.Sprintf("%d -> %d", baseScan.Report.TLS.Score, targetScan.Report.TLS.Score)
		}
		if baseScan.Report.TLS.TLSVersion != targetScan.Report.TLS.TLSVersion {
			diff.TLSChanges["tls_version"] = fmt.Sprintf("%s -> %s", baseScan.Report.TLS.TLSVersion, targetScan.Report.TLS.TLSVersion)
		}
	}

	// AI summary
	diff.AISummaryChange = fmt.Sprintf("%s -> %s", baseScan.Report.AI.Classification, targetScan.Report.AI.Classification)

	return diff, nil
}

