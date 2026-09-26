# Report Engine & Multi-Format Exporters

## 1. Overview

The VortexDNS Report Engine compiles scan telemetry, findings, and mitigations into publication-grade executive and engineering reports.

Supported Formats:
- **HTML Report**: Responsive, dark/light theme compatible, print-optimized document.
- **PDF Report**: Vector PDF compiled via headless Chromium/Edge with print media queries.
- **JSON**: Full hierarchical scan object with SHA-256 cryptographic verification.
- **JSONL (NDJSON)**: Line-delimited streaming export for data lakes and SIEM ingestion.
- **CSV**: RFC 4180 compliant tabular export of findings and remediations.

---

## 2. 25-Section Report Structure

Every generated report follows a standardized 25-section architecture:

1. **Cover Page**: VortexDNS branded cover, target domain, scan ID, timestamp, and versioning.
2. **Executive Summary**: High-level website health, performance summary, TLS grade, and AI status.
3. **Scan Scope & Boundary**: Target URL, network addresses, boundaries, and timestamps.
4. **Target Information**: Scheme, host, port, resolved IP addresses, and canonical status.
5. **Architecture Overview**: Inferred frontend, backend, server, and edge topologies.
6. **Lighthouse Quality Analysis**: Performance, Accessibility, Best Practices, SEO, and PWA scores.
7. **Core Web Vitals**: FCP, LCP, TBT, CLS, Speed Index, and INP metrics.
8. **TLS & Certificate Analysis**: Cipher suite, protocol, validity, and expiration timeline.
9. **HTTP Protocol Support**: HTTP/1.1, HTTP/2, and HTTP/3 / QUIC availability.
10. **Security Headers & Cookies**: HSTS, CSP, X-Content-Type-Options, Referrer-Policy, and cookie flags.
11. **Technology Stack Detection**: Multi-signal identified frameworks with confidence and evidence.
12. **AI-Native Detection**: AI SDKs, inference endpoints, streaming protocols, and vector stores.
13. **Network Telemetry**: Request counts, byte totals, and first-party vs. third-party split.
14. **Architecture Route Graph**: Topology map connecting the browser, edge, API, and providers.
15. **PWA Analysis**: Manifest compliance, service worker registration, and installability.
16. **Performance Findings**: Latency bottlenecks, blocking assets, and compression gaps.
17. **Security Configuration Findings**: Missing headers, insecure cookies, and CORS policies.
18. **AI Architecture & Security Findings**: Exposed keys, unprotected inference, or missing rate limits.
19. **Risk Severity Matrix**: Visual distribution across Critical, High, Medium, Low, and Info.
20. **Detailed Actionable Mitigation Plan**: Concrete code and configuration fixes.
21. **Prioritized Action Plan**: Grouped into Immediate, Short-term, Medium-term, and Strategic.
22. **Technical Evidence Appendix**: Concrete HTTP responses, headers, and script paths observed.
23. **Methodology**: Explanation of safe scanning routines, algorithms, and thresholds.
24. **Limitations & Disclaimer**: Explicit disclaimer regarding non-intrusive external visibility.
25. **Cryptographic Integrity & Metadata**: Report hash (SHA-256) and engine verification details.

---

## 3. PDF Engine Architecture & Graceful Fallback

```text
       Scan Data
           |
           v
      Report Model
           |
           v
    HTML Template (Print-CSS)
           |
           +-----------------------------+
           |                             |
           v                             v
   [ Headless Chrome / Edge ]    [ Engine Unavailable Fallback ]
           |                             |
           v                             v
       Report.pdf               HTML Report Displayed
                           (Prompt to Print/Save as PDF via Browser)
```

- VortexDNS automatically discovers headless Chromium or Microsoft Edge on the host (`chrome.exe`, `msedge.exe`, `google-chrome`, `chromium`).
- It executes `chrome --headless=new --disable-gpu --print-to-pdf=<dest> <source.html>`.
- If no headless browser is detected, the API reports `engine: unavailable` via `/api/v1/scans/engine-status` and delivers the clean HTML report directly so the user can print to PDF natively without errors.
