# Observability Architecture

## 1. Overview

VortexDNS incorporates a unified three-pillar observability framework encompassing **Metrics**, **Logs**, and **Distributed Tracing**, extended to cover the Website Scanner and Web Intelligence subsystem.

---

## 2. Prometheus Metrics

Scanner metrics are exposed via the `/metrics` endpoint with normalized, bounded labels:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `vortexdns_scan_total` | Counter | Total number of scans requested |
| `vortexdns_scan_active` | Gauge | Currently running concurrent scans |
| `vortexdns_scan_duration_seconds` | Summary | End-to-end scan duration distribution |
| `vortexdns_scan_pages_total` | Counter | Total pages inspected during crawls |
| `vortexdns_scan_requests_total` | Counter | Total HTTP network requests issued |
| `vortexdns_scan_bytes_total` | Counter | Total bytes downloaded across scans |
| `vortexdns_scan_findings_total` | Counter | Total identified security/quality findings |
| `vortexdns_scan_failures_total` | Counter | Total scans failed due to network/timeout |
| `vortexdns_scan_reports_total` | Counter | Total reports generated and exported |

---

## 3. OpenTelemetry Distributed Tracing

The scanner subsystem generates OpenTelemetry-compatible tracing spans across the execution pipeline:

```text
[scan.create]
  │
  ├── [scan.resolve_dns]
  ├── [scan.tls]
  ├── [scan.fetch]
  ├── [scan.tech.detect]
  ├── [scan.ai.detect]
  ├── [scan.lighthouse]
  └── [scan.report.generate]
        ├── [scan.export.jsonl]
        ├── [scan.export.csv]
        └── [scan.export.pdf]
```

### Trace Safety Rules
- Spans only record normalized domain names and target hostnames (`target.host: example.com`).
- URLs with query parameters or session IDs are never attached to span attributes.
- Sensitive headers (Authorization, Cookie, Set-Cookie) and extracted API tokens are strictly excluded from span events and baggage.

---

## 4. Structured Logging

Logs use structured JSON formatting with component tags:

```json
{
  "level": "info",
  "component": "scanner",
  "scan_id": "scan_6798b3f2a10",
  "target_host": "example.com",
  "event": "tls_scan_completed",
  "duration_ms": 218
}
```

### Sanitization Policy
The logger enforces strict redaction:
- No raw passwords, cookies, or authorization tokens.
- Discovered API secrets are scrubbed to `sk-proj-****************91Ax` prior to logging.
- Internal private IP addresses or network topology paths are not leaked in log outputs.
