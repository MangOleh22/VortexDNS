# Scanner Security & SSRF Protection Architecture

## 1. Threat Model & Principles

Scanning user-supplied arbitrary URLs introduces critical security risks:
- **Server-Side Request Forgery (SSRF)**: Attacking internal microservices, management APIs, or cloud provider instance metadata.
- **DNS Rebinding Attacks**: Resolving to a benign public IP at validation time, and returning `127.0.0.1` or `169.254.169.254` at connection time.
- **Redirect Hijacking**: Responding with an HTTP 301/302/307 redirect targeting private networks or loopback interfaces.
- **Encoded IP Bypasses**: Obfuscated decimal, octal, hex, or dotted shorthand IP formats.
- **Denial of Service**: Giant payloads, recursive compression bombs, or redirect loops.

VortexDNS strictly adheres to a **Safe, Non-Destructive, Read-Only Public Surface Analysis** policy:
- No aggressive vulnerability exploitation or penetration testing payloads.
- No credential stuffing or authentication brute forcing.
- Zero access to private or local networks.

---

## 2. Blocked Network Ranges & Metadata Endpoints

VortexDNS validates all targets against the following blocked CIDR blocks and addresses:

| Network Category | Subnets / Targets | Purpose |
| :--- | :--- | :--- |
| **This Network** | `0.0.0.0/8` | Self-identification |
| **IPv4 Loopback** | `127.0.0.0/8` | Localhost loopback addresses |
| **RFC 1918 Private Class A** | `10.0.0.0/8` | Internal corporate/home networks |
| **RFC 1918 Private Class B** | `172.16.0.0/12` | Internal corporate/container subnets |
| **RFC 1918 Private Class C** | `192.168.0.0/16` | Internal LANs |
| **Carrier Grade NAT** | `100.64.0.0/10` | Shared address space |
| **Link-Local & Cloud Metadata** | `169.254.0.0/16` | AWS/GCP/Azure `169.254.169.254` |
| **Documentation & Benchmark** | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15` | Reserved test ranges |
| **Multicast & Reserved** | `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32` | Non-routable addresses |
| **IPv6 Loopback & Unspecified** | `::1/128`, `::/128` | Localhost IPv6 |
| **IPv6 Unique Local (ULA)** | `fc00::/7` | Private IPv6 |
| **IPv6 Link-Local** | `fe80::/10` | Internal link addresses |
| **Metadata Hostnames** | `instance-data`, `metadata.google.internal`, `metadata`, `fd00:ec2::254` | Cloud hypervisor metadata |

---

## 3. Defense-in-Depth Mechanisms

### 3.1 Pre-Resolution and Encoded IPv4 Detection
Before attempting network calls, target URLs are parsed and inspected:
- Schemes are restricted strictly to `http://` and `https://`.
- Userinfo (`http://user:pass@host`) is rejected outright to prevent parser confusion.
- Integer formats (`http://2130706433`), hexadecimal (`http://0x7f000001`), octal (`http://017700000001`), and shorthand dotted formats (`http://127.1`) are detected, normalized, and blocked.

### 3.2 DNS Rebinding Protection via `SafeDialer`
To defeat Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks:
- The standard library `http.Transport` is configured with a custom `SafeDialer`.
- The `Control` socket hook verifies the target IP address immediately prior to socket connection (`syscall.RawConn`).
- If an address resolves to a private or blocked IP at dial time, the connection is instantly aborted.

### 3.3 Strict Redirect Revalidation
- HTTP redirect handling enforces a maximum of 5 redirects.
- Redirect loops are tracked in an origin history set and terminated.
- Every intermediate redirect destination URL is passed back through `ValidateTargetURL`. If a redirect points to `127.0.0.1`, `localhost`, or a private IP, the client immediately terminates with an error.

### 3.4 Secret Redaction Policy
When scanning public JavaScript bundles and HTML source for AI configurations or exposed keys:
- Discovered tokens (e.g. OpenAI `sk-proj-`, Anthropic `sk-ant-`, AWS `AKIA`, Google API keys) are **never** stored in plain text, logged, or emitted in API payloads.
- The redaction engine preserves safe token prefixes for identification and masks all payload entropy:
  `sk-proj-****************91Ax`
- Secrets are not validated, tested, or transmitted externally.
