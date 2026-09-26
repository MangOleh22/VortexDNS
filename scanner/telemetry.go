package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// ScannerMetrics maintains Prometheus-style atomic counters.
type ScannerMetrics struct {
	ScanTotal           int64
	ScanActive          int64
	ScanDurationSeconds int64
	ScanPagesTotal      int64
	ScanRequestsTotal   int64
	ScanBytesTotal      int64
	ScanFindingsTotal   int64
	ScanFailuresTotal   int64
	ScanReportsTotal    int64
	ExportRequestsTotal int64
	ExportBytesTotal    int64
}

// Global metrics tracker for website intelligence
var Metrics ScannerMetrics

// IncScanTotal increments total scans counter.
func IncScanTotal() { atomic.AddInt64(&Metrics.ScanTotal, 1) }

// IncScanActive increments active scans gauge.
func IncScanActive() { atomic.AddInt64(&Metrics.ScanActive, 1) }

// DecScanActive decrements active scans gauge.
func DecScanActive() { atomic.AddInt64(&Metrics.ScanActive, -1) }

// AddScanDuration records scan duration.
func AddScanDuration(seconds int64) { atomic.AddInt64(&Metrics.ScanDurationSeconds, seconds) }

// AddScanPages records crawled pages.
func AddScanPages(pages int64) { atomic.AddInt64(&Metrics.ScanPagesTotal, pages) }

// AddScanRequests records HTTP requests performed.
func AddScanRequests(reqs int64) { atomic.AddInt64(&Metrics.ScanRequestsTotal, reqs) }

// AddScanBytes records bytes transferred.
func AddScanBytes(bytes int64) { atomic.AddInt64(&Metrics.ScanBytesTotal, bytes) }

// AddScanFindings records findings generated.
func AddScanFindings(findings int64) { atomic.AddInt64(&Metrics.ScanFindingsTotal, findings) }

// IncScanFailures increments failure counter.
func IncScanFailures() { atomic.AddInt64(&Metrics.ScanFailuresTotal, 1) }

// IncScanReports increments reports produced.
func IncScanReports() { atomic.AddInt64(&Metrics.ScanReportsTotal, 1) }

// IncExportRequests increments export requests.
func IncExportRequests() { atomic.AddInt64(&Metrics.ExportRequestsTotal, 1) }

// AddExportBytes records bytes exported.
func AddExportBytes(b int64) { atomic.AddInt64(&Metrics.ExportBytesTotal, b) }

// PrometheusMetricsOutput formats scanner metrics into standard Prometheus exposition format.
func PrometheusMetricsOutput() string {
	return fmt.Sprintf(`# HELP vortexdns_scan_total Total website intelligence scans initiated.
# TYPE vortexdns_scan_total counter
vortexdns_scan_total %d

# HELP vortexdns_scan_active Currently active website scans.
# TYPE vortexdns_scan_active gauge
vortexdns_scan_active %d

# HELP vortexdns_scan_duration_seconds Aggregate seconds spent scanning.
# TYPE vortexdns_scan_duration_seconds counter
vortexdns_scan_duration_seconds %d

# HELP vortexdns_scan_pages_total Total website pages inspected.
# TYPE vortexdns_scan_pages_total counter
vortexdns_scan_pages_total %d

# HELP vortexdns_scan_requests_total Total HTTP requests performed by scanner.
# TYPE vortexdns_scan_requests_total counter
vortexdns_scan_requests_total %d

# HELP vortexdns_scan_bytes_total Total bytes received by scanner.
# TYPE vortexdns_scan_bytes_total counter
vortexdns_scan_bytes_total %d

# HELP vortexdns_scan_findings_total Total security and quality findings discovered.
# TYPE vortexdns_scan_findings_total counter
vortexdns_scan_findings_total %d

# HELP vortexdns_scan_failures_total Total failed scans.
# TYPE vortexdns_scan_failures_total counter
vortexdns_scan_failures_total %d

# HELP vortexdns_scan_reports_total Total intelligence reports generated.
# TYPE vortexdns_scan_reports_total counter
vortexdns_scan_reports_total %d

# HELP vortexdns_export_requests_total Total export operations requested.
# TYPE vortexdns_export_requests_total counter
vortexdns_export_requests_total %d

# HELP vortexdns_export_bytes_total Total bytes transferred via exports.
# TYPE vortexdns_export_bytes_total counter
vortexdns_export_bytes_total %d
`,
		atomic.LoadInt64(&Metrics.ScanTotal),
		atomic.LoadInt64(&Metrics.ScanActive),
		atomic.LoadInt64(&Metrics.ScanDurationSeconds),
		atomic.LoadInt64(&Metrics.ScanPagesTotal),
		atomic.LoadInt64(&Metrics.ScanRequestsTotal),
		atomic.LoadInt64(&Metrics.ScanBytesTotal),
		atomic.LoadInt64(&Metrics.ScanFindingsTotal),
		atomic.LoadInt64(&Metrics.ScanFailuresTotal),
		atomic.LoadInt64(&Metrics.ScanReportsTotal),
		atomic.LoadInt64(&Metrics.ExportRequestsTotal),
		atomic.LoadInt64(&Metrics.ExportBytesTotal),
	)
}

// Span represents an OpenTelemetry-compatible tracing span.
type Span struct {
	Name       string
	ScanID     string
	TargetHost string
	StartTime  time.Time
	Attributes map[string]interface{}
}

// StartSpan creates and begins a new conceptual OpenTelemetry trace span.
func StartSpan(ctx context.Context, name, scanID, targetHost string) (context.Context, *Span) {
	s := &Span{
		Name:       name,
		ScanID:     scanID,
		TargetHost: targetHost,
		StartTime:  time.Now(),
		Attributes: make(map[string]interface{}),
	}
	s.Attributes["scan.id"] = scanID
	s.Attributes["target.host"] = targetHost
	return ctx, s
}

// SetAttribute records a non-sensitive trace attribute.
func (s *Span) SetAttribute(key string, val interface{}) {
	if s != nil {
		s.Attributes[key] = val
	}
}

// End finishes the trace span and emits structured log telemetry.
func (s *Span) End() {
	if s == nil {
		return
	}
	elapsed := time.Since(s.StartTime).Milliseconds()
	LogStructured("info", "scanner.trace", s.ScanID, s.Name, map[string]interface{}{
		"duration_ms": elapsed,
		"attributes":  s.Attributes,
	})
}

// LogStructured writes a sanitised, structured log entry without leaking authorization or cookies.
func LogStructured(level, component, scanID, event string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"component": component,
		"scan_id":   scanID,
		"event":     event,
	}
	for k, v := range fields {
		// Strict blacklist for sensitive parameter logging
		kLower := k
		if kLower == "cookie" || kLower == "authorization" || kLower == "password" || kLower == "token" || kLower == "secret" {
			entry[k] = "[REDACTED]"
		} else {
			entry[k] = v
		}
	}

	b, err := json.Marshal(entry)
	if err == nil {
		log.Println(string(b))
	}
}
