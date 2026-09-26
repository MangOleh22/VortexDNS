# Scan Schema Specification

## 1. Overview

VortexDNS produces structured, normalized intelligence reports for website scans. The schema is versioned to support forward compatibility without breaking consumers.

- **Schema Version**: `1.0.0`
- **Scanner Engine Version**: `1.0.0`
- **Output Formats**: `application/json`, `application/x-ndjson` (JSONL), `text/csv`, `application/pdf`

---

## 2. Top-Level Report JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VortexDNSScanReport",
  "type": "object",
  "required": [
    "scan_id",
    "target",
    "generated_at",
    "schema_version",
    "scanner_version",
    "summary"
  ],
  "properties": {
    "scan_id": { "type": "string" },
    "target": {
      "type": "object",
      "required": ["url", "host", "scheme", "port"],
      "properties": {
        "url": { "type": "string" },
        "host": { "type": "string" },
        "scheme": { "type": "string" },
        "port": { "type": "integer" }
      }
    },
    "generated_at": { "type": "string", "format": "date-time" },
    "schema_version": { "type": "string" },
    "scanner_version": { "type": "string" },
    "sha256": { "type": "string" },
    "summary": {
      "type": "object",
      "properties": {
        "website_health": { "type": "string" },
        "performance_score": { "type": "number" },
        "tls_posture": { "type": "string" },
        "security_score": { "type": "number" },
        "tech_stack_count": { "type": "integer" },
        "ai_native_status": { "type": "string" },
        "critical_count": { "type": "integer" },
        "high_count": { "type": "integer" },
        "medium_count": { "type": "integer" },
        "low_count": { "type": "integer" },
        "info_count": { "type": "integer" }
      }
    },
    "lighthouse": {
      "type": "object",
      "properties": {
        "status": { "type": "string" },
        "performance": { "type": "number" },
        "accessibility": { "type": "number" },
        "best_practices": { "type": "number" },
        "seo": { "type": "number" },
        "pwa": { "type": "number" },
        "metrics": {
          "type": "object",
          "properties": {
            "fcp_ms": { "type": "number" },
            "lcp_ms": { "type": "number" },
            "tbt_ms": { "type": "number" },
            "cls": { "type": "number" },
            "si_ms": { "type": "number" },
            "tti_ms": { "type": "number" },
            "inp_ms": { "type": "number" }
          }
        }
      }
    },
    "tls": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean" },
        "score": { "type": "integer" },
        "grade": { "type": "string" },
        "protocol": { "type": "string" },
        "cipher_suite": { "type": "string" },
        "alpn": { "type": "array", "items": { "type": "string" } },
        "ocsp_stapled": { "type": "boolean" },
        "leaf": { "type": "object" },
        "chain": { "type": "array", "items": { "type": "object" } },
        "findings": { "type": "array", "items": { "type": "object" } }
      }
    },
    "http": {
      "type": "object",
      "properties": {
        "negotiated_protocol": { "type": "string" },
        "http2_supported": { "type": "boolean" },
        "http3_supported": { "type": "boolean" },
        "alt_svc": { "type": "string" },
        "security_headers": { "type": "array", "items": { "type": "object" } },
        "cookies": { "type": "array", "items": { "type": "object" } },
        "cors": { "type": "object" }
      }
    },
    "technologies": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["technology", "category", "confidence", "evidence"],
        "properties": {
          "technology": { "type": "string" },
          "category": { "type": "string" },
          "confidence": { "type": "number" },
          "evidence": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "ai": {
      "type": "object",
      "properties": {
        "classification": { "type": "string" },
        "confidence": { "type": "number" },
        "findings": { "type": "array", "items": { "type": "object" } },
        "secrets": { "type": "array", "items": { "type": "object" } },
        "observability_gaps": { "type": "array", "items": { "type": "string" } }
      }
    },
    "pwa": { "type": "object" },
    "network": {
      "type": "object",
      "properties": {
        "requests_total": { "type": "integer" },
        "bytes_received": { "type": "integer" },
        "first_party_requests": { "type": "integer" },
        "third_party_requests": { "type": "integer" },
        "requests": { "type": "array", "items": { "type": "object" } },
        "third_parties": { "type": "array", "items": { "type": "object" } }
      }
    },
    "route_graph": {
      "type": "object",
      "properties": {
        "nodes": { "type": "array", "items": { "type": "object" } },
        "edges": { "type": "array", "items": { "type": "object" } }
      }
    },
    "findings": {
      "type": "object",
      "properties": {
        "security": { "type": "array", "items": { "type": "object" } },
        "performance": { "type": "array", "items": { "type": "object" } }
      }
    },
    "mitigations": {
      "type": "object",
      "properties": {
        "immediate": { "type": "array", "items": { "type": "object" } },
        "short_term": { "type": "array", "items": { "type": "object" } },
        "medium_term": { "type": "array", "items": { "type": "object" } },
        "strategic": { "type": "array", "items": { "type": "object" } }
      }
    }
  }
}
```

---

## 3. Streaming JSONL Record Types

The `/api/v1/scans/{id}/export/jsonl` endpoint streams JSON lines with independent parsing semantics:

| Line Type (`type`) | Payload Description |
| :--- | :--- |
| `scan` | Scan ID, target information, timestamp, and versioning |
| `summary` | Aggregated health scores, finding counts, and AI status |
| `lighthouse` | Performance, accessibility, SEO scores, and Core Web Vitals |
| `tls` | Cipher suite, protocol, leaf cert, and expiration |
| `http` | HTTP/2 and HTTP/3 support, Alt-Svc header, and CORS status |
| `technology` | Technology name, category, confidence, and evidence lines |
| `ai_finding` | AI provider, technology, capability, risk, and evidence |
| `exposed_secret` | Redacted credential token, secret type, and location |
| `finding` | Normalized security/performance finding with remediation |
| `mitigation` | Prioritized remediation item with verification steps |
| `route_node` | Architecture node in route graph |
| `route_edge` | Architecture edge in route graph |
