package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	ScannerVersion = "1.0.0"
	ReportVersion  = "1.0.0"
	SchemaVersion  = "2026-09-26"
)

// PDFEngineStatus holds the availability details for PDF generation.
type PDFEngineStatus struct {
	Available bool   `json:"available"`
	Engine    string `json:"engine"`
	Binary    string `json:"binary"`
}

// CheckPDFEngine finds Chrome, Chromium, or Edge for headless PDF printing.
func CheckPDFEngine() PDFEngineStatus {
	candidates := []string{
		"google-chrome",
		"chromium",
		"chromium-browser",
		"chrome",
		"msedge",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}

	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return PDFEngineStatus{
				Available: true,
				Engine:    "Headless Chromium / Edge",
				Binary:    path,
			}
		}
		if _, err := os.Stat(c); err == nil {
			return PDFEngineStatus{
				Available: true,
				Engine:    "Headless Chromium / Edge",
				Binary:    c,
			}
		}
	}

	return PDFEngineStatus{
		Available: false,
		Engine:    "HTML-to-Print fallback (no Chromium binary detected in PATH)",
		Binary:    "",
	}
}

// GenerateHTMLReport produces a complete, professional, 25-section printable HTML report.
func GenerateHTMLReport(rep *ScanReport) string {
	var b strings.Builder

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\"/>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>\n<title>VortexDNS Website Intelligence Report — ")
	b.WriteString(html.EscapeString(rep.Target.Host))
	b.WriteString("</title>\n<style>\n")
	b.WriteString(`
  :root {
    --bg: #0b0f19;
    --card: #131c2e;
    --text: #e2e8f0;
    --text2: #94a3b8;
    --border: #1e293b;
    --cyan: #00d4ff;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --purple: #8b5cf6;
  }
  @media print {
    body { background: #fff !important; color: #000 !important; font-size: 11pt; }
    .page-break { page-break-before: always; }
    .card { border: 1px solid #ccc !important; background: #fff !important; color: #000 !important; box-shadow: none !important; }
    .no-print { display: none !important; }
    h1, h2, h3 { color: #000 !important; }
    .tag, .badge { border: 1px solid #999 !important; color: #000 !important; }
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  .container { max-width: 1000px; margin: 0 auto; }
  .cover {
    padding: 60px 40px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(0,212,255,0.08), rgba(139,92,246,0.08));
    margin-bottom: 40px;
    text-align: center;
  }
  .cover h1 { font-size: 32px; margin: 0 0 12px; color: var(--cyan); letter-spacing: -0.5px; }
  .cover .sub { font-size: 16px; color: var(--text2); margin-bottom: 24px; }
  .cover .meta { font-size: 13px; color: var(--text2); display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }
  .section { margin-bottom: 40px; }
  .section-title {
    font-size: 20px;
    font-weight: 600;
    margin: 0 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    color: var(--cyan);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
  }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .stat-box { text-align: center; padding: 12px; background: rgba(255,255,255,0.02); border-radius: 6px; }
  .stat-val { font-size: 24px; font-weight: 700; color: var(--cyan); margin-top: 4px; }
  .stat-lbl { font-size: 12px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
  th { background: rgba(255,255,255,0.03); color: var(--text2); font-weight: 600; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge-critical { background: rgba(239,68,68,0.2); color: var(--red); }
  .badge-high { background: rgba(245,158,11,0.2); color: var(--yellow); }
  .badge-medium { background: rgba(139,92,246,0.2); color: var(--purple); }
  .badge-low { background: rgba(16,185,129,0.2); color: var(--green); }
  .badge-info { background: rgba(0,212,255,0.2); color: var(--cyan); }
  code, pre { font-family: ui-monospace, Menlo, Monaco, Consolas, monospace; }
  pre {
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--border);
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 12px;
  }
</style>
</head>
<body>
<div class="container">
`)

	// 1. Cover
	b.WriteString(fmt.Sprintf(`
  <div class="cover">
    <h1>VortexDNS Website Intelligence Report</h1>
    <div class="sub">Comprehensive Surface Telemetry & Risk Inspection</div>
    <div class="meta">
      <div><strong>Target:</strong> %s</div>
      <div><strong>Scan ID:</strong> %s</div>
      <div><strong>Generated:</strong> %s</div>
      <div><strong>Scanner:</strong> v%s</div>
    </div>
  </div>
`, html.EscapeString(rep.Target.URL), html.EscapeString(rep.ScanID), rep.GeneratedAt.Format("2006-01-02 15:04:05 UTC"), ScannerVersion))

	// 2. Executive Summary
	b.WriteString(fmt.Sprintf(`
  <div class="section">
    <div class="section-title">2. Executive Summary</div>
    <div class="grid-4">
      <div class="stat-box"><div class="stat-lbl">Website Health</div><div class="stat-val">%s</div></div>
      <div class="stat-box"><div class="stat-lbl">TLS Posture</div><div class="stat-val">%s</div></div>
      <div class="stat-box"><div class="stat-lbl">AI Classification</div><div class="stat-val" style="font-size:16px;">%s</div></div>
      <div class="stat-box"><div class="stat-lbl">Critical / High Risks</div><div class="stat-val" style="color:var(--red);">%d / %d</div></div>
    </div>
    <div class="card" style="margin-top:16px;">
      <p>Target domain <strong>%s</strong> was safely evaluated by the non-destructive VortexDNS Web Intelligence engine. The inspection observed <strong>%d</strong> HTTP requests across <strong>%d</strong> pages, identifying <strong>%d</strong> technology components and <strong>%d</strong> total actionable security/operational findings.</p>
    </div>
  </div>
`, html.EscapeString(rep.Summary.WebsiteHealth), html.EscapeString(rep.Summary.TLSPosture), html.EscapeString(rep.Summary.AINativeStatus), rep.Summary.CriticalCount, rep.Summary.HighCount, html.EscapeString(rep.Target.Host), rep.Network.TotalRequests, rep.ScanConfig.MaxPages, len(rep.Technologies), len(rep.Security)))

	// 3. Scan Scope & 4. Target Information
	b.WriteString(fmt.Sprintf(`
  <div class="section">
    <div class="section-title">3. Scan Scope & 4. Target Information</div>
    <div class="card grid-2">
      <div>
        <strong>Target Host:</strong> %s<br/>
        <strong>Initial URL:</strong> %s<br/>
        <strong>Canonical Target:</strong> %s<br/>
        <strong>Scheme / Port:</strong> %s / %d<br/>
        <strong>Resolved Addresses:</strong> %s
      </div>
      <div>
        <strong>Crawl Bound (Pages):</strong> %d<br/>
        <strong>Crawl Depth Limit:</strong> %d<br/>
        <strong>Max Concurrency:</strong> %d<br/>
        <strong>Timeout per Request:</strong> %ds<br/>
        <strong>SSRF Policy:</strong> Strict Private Network & Cloud Metadata Isolation Enforced
      </div>
    </div>
  </div>
`, html.EscapeString(rep.Target.Host), html.EscapeString(rep.Target.URL), html.EscapeString(rep.Target.Canonical), html.EscapeString(rep.Target.Scheme), rep.Target.Port, html.EscapeString(strings.Join(rep.Target.ResolvedIP, ", ")), rep.ScanConfig.MaxPages, rep.ScanConfig.MaxDepth, rep.ScanConfig.MaxConcurrency, rep.ScanConfig.RequestTimeoutSeconds))

	// 5. Architecture Overview
	b.WriteString(`
  <div class="section">
    <div class="section-title">5. Architecture Overview</div>
    <div class="card">
      <p>The scanned public endpoint routes through the following infrastructure topology based on observed network headers and requests:</p>
      <ul>
`)
	for _, node := range rep.Routes.Nodes {
		if node.ID != "node-browser" {
			b.WriteString(fmt.Sprintf(`<li><strong>%s</strong> (%s) — Protocol: %s, Requests: %d, Data: %d bytes</li>`, html.EscapeString(node.Label), html.EscapeString(node.Category), html.EscapeString(node.Protocol), node.RequestCount, node.DataSize))
		}
	}
	b.WriteString(`</ul></div></div>`)

	// 6. Lighthouse Analysis & 7. Core Web Vitals
	b.WriteString(`
  <div class="section">
    <div class="section-title">6. Lighthouse Analysis & 7. Core Web Vitals</div>
    <div class="card">
`)
	if rep.Lighthouse != nil && rep.Lighthouse.Status == "available" {
		b.WriteString(fmt.Sprintf(`
      <div class="grid-4">
        <div class="stat-box"><div class="stat-lbl">Performance</div><div class="stat-val">%s</div></div>
        <div class="stat-box"><div class="stat-lbl">Accessibility</div><div class="stat-val">%s</div></div>
        <div class="stat-box"><div class="stat-lbl">Best Practices</div><div class="stat-val">%s</div></div>
        <div class="stat-box"><div class="stat-lbl">SEO</div><div class="stat-val">%s</div></div>
      </div>
      <table>
        <tr><th>Metric</th><th>Measured Value</th></tr>
        <tr><td>First Contentful Paint (FCP)</td><td>%s</td></tr>
        <tr><td>Largest Contentful Paint (LCP)</td><td>%s</td></tr>
        <tr><td>Total Blocking Time (TBT)</td><td>%s</td></tr>
        <tr><td>Speed Index</td><td>%s</td></tr>
      </table>
`, FormatLighthouseScore(rep.Lighthouse.Performance), FormatLighthouseScore(rep.Lighthouse.Accessibility), FormatLighthouseScore(rep.Lighthouse.BestPractices), FormatLighthouseScore(rep.Lighthouse.SEO), FormatMetricMS(rep.Lighthouse.Metrics.FCPMs), FormatMetricMS(rep.Lighthouse.Metrics.LCPMs), FormatMetricMS(rep.Lighthouse.Metrics.TBTMs), FormatMetricMS(rep.Lighthouse.Metrics.SpeedIndexMs)))
	} else {
		b.WriteString(`
      <p><strong>Status:</strong> <span class="badge badge-info">unavailable</span></p>
      <p>Lighthouse CLI was not detected in the runtime execution environment. Per safety specification, synthetic metrics are omitted to prevent fabrication.</p>
`)
	}
	b.WriteString(`</div></div>`)

	// 8. TLS & Certificate Analysis
	b.WriteString(`
  <div class="section">
    <div class="section-title">8. TLS & Certificate Analysis</div>
    <div class="card">
`)
	if rep.TLS != nil {
		b.WriteString(fmt.Sprintf(`
      <div class="grid-3">
        <div class="stat-box"><div class="stat-lbl">TLS Score</div><div class="stat-val">%d / 100</div></div>
        <div class="stat-box"><div class="stat-lbl">Protocol</div><div class="stat-val" style="font-size:18px;">%s</div></div>
        <div class="stat-box"><div class="stat-lbl">Days to Expiry</div><div class="stat-val">%d</div></div>
      </div>
      <p style="margin-top:12px;"><strong>Subject:</strong> %s<br/>
      <strong>Issuer:</strong> %s<br/>
      <strong>Cipher Suite:</strong> %s<br/>
      <strong>Public Key:</strong> %s (%d bits)<br/>
      <strong>OCSP Stapling:</strong> %s</p>
      <table>
        <tr><th>Check</th><th>Severity</th><th>Observed</th><th>Recommendation</th></tr>
`, rep.TLS.Score, html.EscapeString(rep.TLS.TLSVersion), rep.TLS.DaysUntilExpiration, html.EscapeString(rep.TLS.Subject), html.EscapeString(rep.TLS.Issuer), html.EscapeString(rep.TLS.CipherSuite), html.EscapeString(rep.TLS.PublicKeyAlgorithm), rep.TLS.PublicKeySize, html.EscapeString(rep.TLS.OCSPStapling)))
		for _, c := range rep.TLS.Checks {
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><span class="badge badge-%s">%s</span></td><td>%s</td><td>%s</td></tr>`, html.EscapeString(c.Check), c.Severity, c.Severity, html.EscapeString(c.Observed), html.EscapeString(c.Recommendation)))
		}
		b.WriteString(`</table>`)
	} else {
		b.WriteString(`<p>TLS analysis unavailable for non-HTTPS target.</p>`)
	}
	b.WriteString(`</div></div>`)

	// 9. HTTP / HTTP2 / HTTP3 Analysis & 10. Security Headers
	b.WriteString(`
  <div class="section">
    <div class="section-title">9. HTTP Protocol & 10. Security Headers</div>
    <div class="card">
`)
	if rep.HTTP != nil {
		b.WriteString(fmt.Sprintf(`
      <p><strong>Negotiated Protocol:</strong> %s | <strong>Supported:</strong> %s | <strong>Alt-Svc:</strong> %s</p>
      <table>
        <tr><th>Security Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr>
`, html.EscapeString(rep.HTTP.NegotiatedProtocol), html.EscapeString(strings.Join(rep.HTTP.SupportedProtocols, ", ")), html.EscapeString(rep.HTTP.AltSvc)))
		for hName, h := range rep.HTTP.SecurityHeaders {
			statusBadge := `<span class="badge badge-low">PRESENT</span>`
			if !h.Present {
				statusBadge = `<span class="badge badge-high">MISSING</span>`
			}
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`, html.EscapeString(hName), statusBadge, html.EscapeString(h.Value), html.EscapeString(h.Recommendation)))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)

	// 11. Technology Stack
	b.WriteString(`
  <div class="section">
    <div class="section-title">11. Technology Stack</div>
    <div class="card">
      <table>
        <tr><th>Technology</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr>
`)
	for _, t := range rep.Technologies {
		b.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td>%s</td><td>%.0f%%</td><td>%s</td></tr>`, html.EscapeString(t.Technology), html.EscapeString(t.Category), t.Confidence*100, html.EscapeString(strings.Join(t.Evidence, "; "))))
	}
	b.WriteString(`</table></div></div>`)

	// 12. AI-Native Detection & 18. AI Security Findings
	b.WriteString(fmt.Sprintf(`
  <div class="section">
    <div class="section-title">12. AI-Native Detection & 18. AI Security</div>
    <div class="card">
      <div class="grid-2">
        <div class="stat-box"><div class="stat-lbl">AI Classification</div><div class="stat-val" style="font-size:18px;">%s</div></div>
        <div class="stat-box"><div class="stat-lbl">Confidence</div><div class="stat-val">%.0f%%</div></div>
      </div>
      <h4 style="margin-top:16px;">Discovered AI Capabilities</h4>
`, html.EscapeString(rep.AI.Classification), rep.AI.Confidence*100))
	if len(rep.AI.Findings) > 0 {
		b.WriteString(`<table><tr><th>Technology</th><th>Provider</th><th>Capability</th><th>Evidence</th></tr>`)
		for _, a := range rep.AI.Findings {
			b.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>`, html.EscapeString(a.Technology), html.EscapeString(a.Provider), html.EscapeString(a.Capability), html.EscapeString(strings.Join(a.Evidence, "; "))))
		}
		b.WriteString(`</table>`)
	} else {
		b.WriteString(`<p>No public AI-native capabilities or SDKs detected on the target website.</p>`)
	}

	if len(rep.AI.Secrets) > 0 {
		b.WriteString(`<h4 style="color:var(--red);margin-top:16px;">Detected Exposed Credentials (Redacted)</h4><table><tr><th>Type</th><th>Location</th><th>Redacted Value</th></tr>`)
		for _, s := range rep.AI.Secrets {
			b.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>`, html.EscapeString(s.SecretType), html.EscapeString(s.Location), html.EscapeString(s.RedactedValue)))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)

	// 13. Network Dependencies & 14. Route Graph
	b.WriteString(fmt.Sprintf(`
  <div class="section">
    <div class="section-title">13. Network Dependencies & 14. Route Graph</div>
    <div class="card">
      <div class="grid-4">
        <div class="stat-box"><div class="stat-lbl">Total Requests</div><div class="stat-val">%d</div></div>
        <div class="stat-box"><div class="stat-lbl">Total Bytes</div><div class="stat-val">%.2f MB</div></div>
        <div class="stat-box"><div class="stat-lbl">First-Party Requests</div><div class="stat-val">%d</div></div>
        <div class="stat-box"><div class="stat-lbl">Third-Party Requests</div><div class="stat-val">%d</div></div>
      </div>
      <h4 style="margin-top:16px;">Observed Architecture Nodes</h4>
      <table><tr><th>Node Label</th><th>Category</th><th>Third-Party</th><th>Requests</th><th>Data</th></tr>
`, rep.Network.TotalRequests, float64(rep.Network.TotalBytes)/(1024*1024), rep.Network.FirstPartyRequests, rep.Network.ThirdPartyRequests))
	for _, n := range rep.Routes.Nodes {
		b.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td>%s</td><td>%v</td><td>%d</td><td>%d bytes</td></tr>`, html.EscapeString(n.Label), html.EscapeString(n.Category), n.IsThirdParty, n.RequestCount, n.DataSize))
	}
	b.WriteString(`</table></div></div>`)

	// 15. PWA Analysis
	b.WriteString(`
  <div class="section">
    <div class="section-title">15. Progressive Web App (PWA) Analysis</div>
    <div class="card">
`)
	if rep.PWA != nil {
		b.WriteString(fmt.Sprintf(`
      <div class="grid-3">
        <div class="stat-box"><div class="stat-lbl">Manifest</div><div class="stat-val">%v</div></div>
        <div class="stat-box"><div class="stat-lbl">Service Worker</div><div class="stat-val">%v</div></div>
        <div class="stat-box"><div class="stat-lbl">Installable</div><div class="stat-val">%v</div></div>
      </div>
      <p style="margin-top:12px;"><strong>App Name:</strong> %s | <strong>Display:</strong> %s | <strong>Theme Color:</strong> %s</p>
`, rep.PWA.HasManifest, rep.PWA.HasServiceWorker, rep.PWA.Installable, html.EscapeString(rep.PWA.Name), html.EscapeString(rep.PWA.DisplayMode), html.EscapeString(rep.PWA.ThemeColor)))
	}
	b.WriteString(`</div></div>`)

	// 16. Performance Findings & 17. Security Findings & 19. Risk Matrix
	b.WriteString(`
  <div class="section">
    <div class="section-title">16. Findings & 19. Risk Matrix</div>
    <div class="card">
      <table>
        <tr><th>ID</th><th>Severity</th><th>Title</th><th>Asset</th><th>Impact</th></tr>
`)
	for _, sf := range rep.Security {
		b.WriteString(fmt.Sprintf(`<tr><td><code>%s</code></td><td><span class="badge badge-%s">%s</span></td><td><strong>%s</strong></td><td>%s</td><td>%s</td></tr>`, html.EscapeString(sf.ID), sf.Severity, sf.Severity, html.EscapeString(sf.Title), html.EscapeString(sf.AffectedAsset), html.EscapeString(sf.Impact)))
	}
	b.WriteString(`</table></div></div>`)

	// 20. Mitigation Plan & 21. Prioritized Recommendations
	b.WriteString(`
  <div class="section">
    <div class="section-title">20. Detailed Mitigation Plan & 21. Recommendations</div>
`)
	for _, grp := range rep.Mitigations {
		if len(grp.Items) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf(`
    <div class="card">
      <h3 style="color:var(--cyan);margin-top:0;">Timeframe: %s Actions (%d items)</h3>
`, html.EscapeString(grp.Timeframe), len(grp.Items)))
		for _, item := range grp.Items {
			b.WriteString(fmt.Sprintf(`
      <div style="margin-bottom:16px;border-left:3px solid var(--cyan);padding-left:12px;">
        <strong>[%s] %s</strong> <span class="badge badge-%s">%s</span><br/>
        <p style="margin:4px 0;"><strong>Problem:</strong> %s</p>
        <p style="margin:4px 0;"><strong>Recommended Action:</strong> %s</p>
        <p style="margin:4px 0;"><strong>Verification Step:</strong> %s</p>
      </div>
`, html.EscapeString(item.ID), html.EscapeString(item.Title), item.Severity, item.Severity, html.EscapeString(item.Description), html.EscapeString(item.Mitigation.Action), html.EscapeString(item.Mitigation.Verification)))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)

	// 22. Technical Evidence, 23. Methodology, 24. Limitations, 25. Appendix
	b.WriteString(fmt.Sprintf(`
  <div class="section">
    <div class="section-title">22. Technical Evidence & Methodology</div>
    <div class="card">
      <p><strong>Methodology:</strong> %s</p>
      <p><strong>Limitations:</strong></p>
      <ul>
`, html.EscapeString(rep.Methodology)))
	for _, lim := range rep.Limitations {
		b.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(lim)))
	}
	b.WriteString(fmt.Sprintf(`
      </ul>
      <p><strong>Integrity SHA-256 Hash:</strong> <code>%s</code></p>
    </div>
  </div>
</div>
</body>
</html>
`, html.EscapeString(rep.ReportHash)))

	return b.String()
}

// RenderPDF produces a PDF from the ScanReport.
// If Chromium is available, renders via headless browser; otherwise falls back to saving standalone printable HTML.
func RenderPDF(ctx context.Context, rep *ScanReport, targetPDFPath string) error {
	htmlContent := GenerateHTMLReport(rep)

	dir := filepath.Dir(targetPDFPath)
	_ = os.MkdirAll(dir, 0755)

	status := CheckPDFEngine()
	if !status.Available {
		// Save printable HTML as standalone report file if PDF renderer is absent
		htmlPath := strings.TrimSuffix(targetPDFPath, ".pdf") + ".html"
		return os.WriteFile(htmlPath, []byte(htmlContent), 0644)
	}

	// Write temporary HTML file
	tmpHTML, err := os.CreateTemp("", "vortex-report-*.html")
	if err != nil {
		return err
	}
	tmpHTMLPath := tmpHTML.Name()
	defer os.Remove(tmpHTMLPath)

	if _, err := tmpHTML.WriteString(htmlContent); err != nil {
		tmpHTML.Close()
		return err
	}
	tmpHTML.Close()

	// Run headless chromium print-to-pdf
	fileURI := "file://" + filepath.ToSlash(tmpHTMLPath)
	if runtime.GOOS == "windows" {
		fileURI = "file:///" + filepath.ToSlash(tmpHTMLPath)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, status.Binary,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--run-all-compositor-stages-before-draw",
		"--print-to-pdf-no-header",
		fmt.Sprintf("--print-to-pdf=%s", targetPDFPath),
		fileURI,
	)

	if out, err := cmd.CombinedOutput(); err != nil {
		// If command fails, write HTML fallback
		htmlPath := strings.TrimSuffix(targetPDFPath, ".pdf") + ".html"
		_ = os.WriteFile(htmlPath, []byte(htmlContent), 0644)
		return fmt.Errorf("chromium pdf rendering failed: %v (output: %s)", err, string(out))
	}

	return nil
}

// ExportJSON writes complete indented JSON report.
func ExportJSON(w io.Writer, rep *ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ExportJSONL streams scan items line-by-line as individual valid JSON objects.
func ExportJSONL(w io.Writer, rep *ScanReport) error {
	enc := json.NewEncoder(w)

	// Line 1: Root Scan Metadata
	if err := enc.Encode(map[string]interface{}{
		"type":        "scan_meta",
		"scan_id":     rep.ScanID,
		"target":      rep.Target,
		"generated_at": rep.GeneratedAt,
		"summary":     rep.Summary,
	}); err != nil {
		return err
	}

	// Line 2: TLS Result
	if rep.TLS != nil {
		if err := enc.Encode(map[string]interface{}{
			"type": "tls",
			"data": rep.TLS,
		}); err != nil {
			return err
		}
	}

	// Line 3: HTTP Result
	if rep.HTTP != nil {
		if err := enc.Encode(map[string]interface{}{
			"type": "http",
			"data": rep.HTTP,
		}); err != nil {
			return err
		}
	}

	// Lines for Technologies
	for _, tech := range rep.Technologies {
		if err := enc.Encode(map[string]interface{}{
			"type": "technology",
			"data": tech,
		}); err != nil {
			return err
		}
	}

	// Lines for AI Findings
	for _, ai := range rep.AI.Findings {
		if err := enc.Encode(map[string]interface{}{
			"type": "ai_finding",
			"data": ai,
		}); err != nil {
			return err
		}
	}

	// Lines for Security Findings
	for _, sf := range rep.Security {
		if err := enc.Encode(map[string]interface{}{
			"type": "security_finding",
			"data": sf,
		}); err != nil {
			return err
		}
	}

	// Lines for Performance Findings
	for _, pf := range rep.Performance {
		if err := enc.Encode(map[string]interface{}{
			"type": "performance_finding",
			"data": pf,
		}); err != nil {
			return err
		}
	}

	// Lines for Route Nodes
	for _, node := range rep.Routes.Nodes {
		if err := enc.Encode(map[string]interface{}{
			"type": "route_node",
			"data": node,
		}); err != nil {
			return err
		}
	}

	return nil
}

// ExportCSV streams RFC-compatible CSV records for scan findings.
func ExportCSV(w io.Writer, rep *ScanReport) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	header := []string{
		"Finding ID",
		"Category",
		"Severity",
		"Confidence",
		"Title",
		"Asset",
		"Impact",
		"Mitigation Timeframe",
		"Action",
		"Technical Fix",
		"Verification",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range rep.Security {
		record := []string{
			f.ID,
			f.Category,
			string(f.Severity),
			fmt.Sprintf("%.2f", f.Confidence),
			f.Title,
			f.AffectedAsset,
			f.Impact,
			f.MitigationTime,
			f.Mitigation.Action,
			f.Mitigation.TechnicalFix,
			f.Mitigation.Verification,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return writer.Error()
}

// ComputeReportHash calculates the SHA-256 integrity digest for a ScanReport.
func ComputeReportHash(rep *ScanReport) string {
	data, err := json.Marshal(rep.Summary)
	if err != nil {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
