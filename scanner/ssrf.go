package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	ErrDisallowedScheme      = errors.New("only http and https schemes are permitted")
	ErrUserInfoNotAllowed    = errors.New("userinfo in target URL is not allowed")
	ErrEmptyHost             = errors.New("target host cannot be empty")
	ErrInvalidPort           = errors.New("invalid port specification")
	ErrPrivateIPBlocked      = errors.New("target resolves to a private, loopback, or reserved address")
	ErrCloudMetadataBlocked  = errors.New("target points to a cloud metadata service endpoint")
	ErrTooManyRedirects      = errors.New("too many redirects encountered")
	ErrRedirectLoopDetected  = errors.New("redirect loop detected")
	ErrDNSResolutionFailed   = errors.New("failed to resolve target domain")
)

// Private and reserved IP networks to block
var blockedIPNets []*net.IPNet

func init() {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",          // "This" network
		"10.0.0.0/8",         // RFC 1918 Private-Use
		"100.64.0.0/10",      // Shared Address Space (CGNAT)
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-Local (including 169.254.169.254 cloud metadata)
		"172.16.0.0/12",      // RFC 1918 Private-Use
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // Documentation (TEST-NET-1)
		"192.88.99.0/24",     // 6to4 Relay Anycast
		"192.168.0.0/16",     // RFC 1918 Private-Use
		"198.18.0.0/15",      // Network Interconnect Device Benchmark Testing
		"198.51.100.0/24",    // Documentation (TEST-NET-2)
		"203.0.113.0/24",     // Documentation (TEST-NET-3)
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for Future Use
		"255.255.255.255/32", // Limited Broadcast

		// IPv6
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"100::/64",      // Discard prefix
		"2001:db8::/32", // Documentation
		"fc00::/7",      // Unique Local (ULA)
		"fe80::/10",     // Link-Local Unicast
		"ff00::/8",      // Multicast
		"64:ff9b::/96",  // IPv4-IPv6 translation
	}

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedIPNets = append(blockedIPNets, ipNet)
		}
	}
}

// Known cloud metadata hostnames
var blockedMetadataHostnames = map[string]bool{
	"instance-data":            true,
	"metadata.google.internal": true,
	"metadata":                 true,
	"169.254.169.254":          true,
	"fd00:ec2::254":            true,
	"localhost":                true,
	"localhost.localdomain":    true,
	"ip6-localhost":            true,
	"ip6-loopback":             true,
}

// IsBlockedIP checks if an IP is in any private, loopback, link-local, or reserved range.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
	isV4 := false
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		isV4 = true
	}

	// Check standard Go helpers first
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	// Check against all explicit CIDR ranges
	for _, block := range blockedIPNets {
		blockIsV4 := block.IP.To4() != nil
		if isV4 && !blockIsV4 {
			continue
		}
		if !isV4 && blockIsV4 {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// tryParseEncodedIPv4 parses decimal, octal, and hex integer formats for IPv4
// (e.g., 2130706433, 0177.0.0.1, 0x7f000001, 127.1).
func tryParseEncodedIPv4(host string) (net.IP, bool) {
	// If it has leading 0x or is purely numeric
	cleanHost := strings.TrimSpace(host)
	if cleanHost == "" {
		return nil, false
	}

	// Check for single integer decimal / hex (e.g. 2130706433 or 0x7f000001)
	if !strings.Contains(cleanHost, ".") && !strings.Contains(cleanHost, ":") {
		var val big.Int
		if _, ok := val.SetString(cleanHost, 0); ok {
			if val.Sign() >= 0 && val.BitLen() <= 32 {
				u32 := val.Uint64()
				return net.IPv4(byte(u32>>24), byte(u32>>16), byte(u32>>8), byte(u32)), true
			}
		}
	}

	// Check for dotted format with octal, hex parts, or shorthand (e.g. 0177.0.0.1, 0x7f.0.0.1, 127.1)
	parts := strings.Split(cleanHost, ".")
	if len(parts) >= 2 && len(parts) <= 4 {
		// Only trigger encoded handling if at least one part has hex (0x), leading 0 (octal), or len(parts) < 4 (shorthand notation)
		isEncoded := len(parts) < 4
		for _, part := range parts {
			if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") || (len(part) > 1 && strings.HasPrefix(part, "0")) {
				isEncoded = true
				break
			}
		}

		if isEncoded {
			allNumeric := true
			var octets []byte
			for _, part := range parts {
				var val big.Int
				if _, ok := val.SetString(part, 0); !ok {
					allNumeric = false
					break
				}
				if val.Sign() < 0 || val.BitLen() > 8 {
					allNumeric = false
					break
				}
				octets = append(octets, byte(val.Uint64()))
			}
			if allNumeric && len(octets) == 4 {
				return net.IPv4(octets[0], octets[1], octets[2], octets[3]), true
			}
			if allNumeric && len(octets) == 2 { // e.g. 127.1 -> 127.0.0.1
				return net.IPv4(octets[0], 0, 0, octets[1]), true
			}
		}
	}

	return nil, false
}

// ValidateTargetURL parses and strictly checks a target URL against SSRF rules.
func ValidateTargetURL(rawURL string) (*url.URL, []net.IP, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil, errors.New("empty URL")
	}

	// Default to https:// if scheme is missing
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Scheme must be http or https
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, nil, ErrDisallowedScheme
	}

	// Disallow userinfo (e.g. http://user:pass@evil.com)
	if parsed.User != nil {
		return nil, nil, ErrUserInfoNotAllowed
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, nil, ErrEmptyHost
	}

	// Normalize hostname
	hostnameLower := strings.ToLower(strings.TrimSuffix(hostname, "."))

	// Check known blocked hostnames (localhost, metadata, etc.)
	if blockedMetadataHostnames[hostnameLower] {
		return nil, nil, fmt.Errorf("%w: %s", ErrCloudMetadataBlocked, hostname)
	}

	// Validate port if present
	portStr := parsed.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, nil, ErrInvalidPort
		}
	}

	// Check if hostname is an encoded IP (hex, octal, decimal)
	if encodedIP, ok := tryParseEncodedIPv4(hostnameLower); ok {
		if IsBlockedIP(encodedIP) {
			return nil, nil, fmt.Errorf("%w (encoded address: %s)", ErrPrivateIPBlocked, encodedIP.String())
		}
		return parsed, []net.IP{encodedIP}, nil
	}

	// Check if direct IP literal
	if ip := net.ParseIP(hostnameLower); ip != nil {
		if IsBlockedIP(ip) {
			return nil, nil, fmt.Errorf("%w: %s", ErrPrivateIPBlocked, ip.String())
		}
		return parsed, []net.IP{ip}, nil
	}

	// DNS Resolution with strict timeout
	resolver := &net.Resolver{
		PreferGo: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "ip", hostnameLower)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDNSResolutionFailed, err)
	}

	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("%w: no A/AAAA records found for %s", ErrDNSResolutionFailed, hostnameLower)
	}

	// Check ALL resolved IPs
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return nil, nil, fmt.Errorf("%w: host %s resolved to blocked address %s", ErrPrivateIPBlocked, hostnameLower, ip.String())
		}
	}

	return parsed, ips, nil
}

// SafeDialer creates a net.Dialer that re-validates the resolved IP on every connection attempt,
// preventing DNS rebinding attacks.
func SafeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip != nil && IsBlockedIP(ip) {
				return fmt.Errorf("%w: connection to %s aborted", ErrPrivateIPBlocked, ip.String())
			}
			return nil
		},
	}
}

// NewSafeTransport constructs an http.Transport with safe dialer and strict limits.
func NewSafeTransport(timeout time.Duration) *http.Transport {
	dialer := SafeDialer(timeout)

	return &http.Transport{
		Proxy:                 nil, // No automatic proxy to prevent internal leaks
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
}

// NewSafeHTTPClient creates a secure http.Client with redirect validation and SSRF defenses.
func NewSafeHTTPClient(timeout time.Duration, maxRedirects int) *http.Client {
	if maxRedirects <= 0 {
		maxRedirects = 5
	}

	transport := NewSafeTransport(timeout)

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}

			// Detect redirect loops
			for _, prior := range via {
				if prior.URL.String() == req.URL.String() {
					return ErrRedirectLoopDetected
				}
			}

			// Validate every redirect destination URL against SSRF
			_, _, err := ValidateTargetURL(req.URL.String())
			if err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}

			return nil
		},
	}

	return client
}
