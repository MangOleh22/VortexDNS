# Web Intelligence & Website Scanner Architecture

## 1. Overview & Objective

The **Web Intelligence / Website Scanner** subsystem in VortexDNS provides real-time, non-destructive, read-oriented telemetry and quality inspection of public internet properties. Built as an additive, decoupled subsystem, it operates without touching or degrading the high-throughput DNS caching engine or core adblocking pipeline.

The scanner collects:
- Real-time website availability and telemetry
- Lighthouse-style quality metrics (Performance, Accessibility, Best Practices, SEO, PWA)
- Complete TLS/SSL certificate lifecycle and configuration details
- HTTP protocol analysis (HTTP/1.1, HTTP/2, HTTP/3 / QUIC via Alt-Svc)
- HTTP security headers and public cookie attributes
- Multi-signal technology stack detection with explainable confidence scoring
- AI-native application indicators, provider SDKs, and streaming routes
- Automated secret detection with mandatory zero-exposure redaction
- Network request telemetry and third-party dependency mapping
- Architecture Route Graph with clustering
- Bounded crawling within strict depth and page count limits
- Actionable, prioritized mitigations (Immediate, Short-term, Medium-term, Strategic)
- Multi-format streaming exports: JSON, JSONL, CSV, and printable 25-section PDF reports

---

## 2. Core Architecture Pipeline

```text
                            VortexDNS Core
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
     DNS Core                  API Plane              Web Intelligence
  (Cache/Blocker)         (REST / SSE Handlers)      (Scanner Subsystem)
                                   |                         |
                                   |                         v
                                   |                  [ Scan Manager ]
                                   |                         |
                                   |             +-----------+-----------+
                                   |             |                       |
                                   |             v                       v
                                   |       SSRF Validator          Worker Pool
                                   |     (DNS Rebinding Pre-check) (Bounded Concurrency)
                                   |             |                       |
                                   |             v                       v
                                   |       Safe HTTP Client         Sub-engines
                                   |                                     |
                                   |                   +-----------------+-----------------+
                                   |                   |        |        |        |        |
                                   |                   v        v        v        v        v
                                   |                  DNS      TLS     HTTP     Tech      AI
                                   |                                              |        |
                                   |                                              v        v
                                   |                                           Findings Aggregator
                                   |                                                   |
                                   |                                                   v
                                   |                                            Mitigation Engine
                                   |                                                   |
                                   |                                                   v
                                   +-------------------------------------------> Report Engine
                                                                                       |
                                                                        +------+-------+------+------+
                                                                        |      |              |      |
                                                                        v      v              v      v
                                                                       JSON  JSONL           CSV    PDF
```

---

## 3. Worker Concurrency & Safety Controls

To guarantee predictable resource utilization and prevent denial-of-service against external servers or memory exhaustion on the host:

1. **Scan Manager Worker Pool**: Concurrency is bounded by a semaphore channel (`chan struct{}`). Default concurrency is 4 simultaneous scans.
2. **Page Crawl Budget**:
   - `max_pages`: 50 pages maximum per scan.
   - `max_depth`: 3 levels deep from target URL.
   - `max_concurrency`: 5 concurrent page workers per scan.
   - `request_timeout`: 15s per HTTP request.
3. **Cancellation propagation**: All network operations take a parent `context.Context`. Cancelling a scan immediately aborts open HTTP connections, background workers, and headless browser processes.
4. **SSE Event Memory Bounding**: Live scan events stream over Server-Sent Events (`/api/v1/scans/{id}/events`). In-memory event buffers are capped at a circular ring buffer of 500 events per scan to prevent memory leaks.
5. **Storage Isolation**: Scan state and reports are saved to dedicated directories (`vortex_db/scans` and `vortex_db/reports`), completely isolated from the DNS query caches and host operating system critical files.
