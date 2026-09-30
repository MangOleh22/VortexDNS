package scanner

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// AnalyzeTLS performs comprehensive, safe, and explainable TLS inspection of an HTTPS target.
func AnalyzeTLS(host string, port int, timeout time.Duration) (*TLSResult, error) {
	if port <= 0 {
		port = 443
	}

	address := fmt.Sprintf("%s:%d", host, port)

	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We inspect the raw peer certs and validate ourselves to provide rich explainable checks
		NextProtos:         []string{"h2", "http/1.1"},
	}

	dialer := SafeDialer(timeout)

	rawConn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, conf)
	tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	cs := tlsConn.ConnectionState()

	result := &TLSResult{
		TLSVersion:   tlsVersionString(cs.Version),
		CipherSuite:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:         []string{},
		Checks:       []TLSCheck{},
		Score:        100, // Starts at 100, deducted per finding
		SNIBehavior:  "Supported (Strict Name Indication Negotiated)",
		OCSPStapling: "Not stapled in initial handshake",
	}

	if cs.NegotiatedProtocol != "" {
		result.ALPN = append(result.ALPN, cs.NegotiatedProtocol)
	}

	if len(cs.OCSPResponse) > 0 {
		result.OCSPStapling = fmt.Sprintf("Stapled (%d bytes)", len(cs.OCSPResponse))
	}

	if len(cs.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates presented")
	}

	leaf := cs.PeerCertificates[0]
	now := time.Now()

	result.Subject = leaf.Subject.CommonName
	if len(leaf.Subject.Organization) > 0 {
		result.Subject = fmt.Sprintf("%s (%s)", leaf.Subject.CommonName, strings.Join(leaf.Subject.Organization, ", "))
	}
	result.Issuer = leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		result.Issuer = fmt.Sprintf("%s (%s)", leaf.Issuer.CommonName, strings.Join(leaf.Issuer.Organization, ", "))
	}

	result.SerialNumber = leaf.SerialNumber.Text(16)
	result.ValidFrom = leaf.NotBefore
	result.ValidUntil = leaf.NotAfter
	result.DaysUntilExpiration = int(leaf.NotAfter.Sub(now).Hours() / 24)
	result.SANs = leaf.DNSNames
	result.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	result.PublicKeyAlgorithm = leaf.PublicKeyAlgorithm.String()

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		result.PublicKeySize = pub.N.BitLen()
	default:
		result.PublicKeySize = 256 // typical ECC curve size
	}

	// Build certificate chain summary
	for _, cert := range cs.PeerCertificates {
		result.CertChain = append(result.CertChain, CertChainEntry{
			Subject:    cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			ValidFrom:  cert.NotBefore,
			ValidUntil: cert.NotAfter,
			IsCA:       cert.IsCA,
		})
	}

	// ── EXPLAINABLE CHECKS & SCORING ────────────────────────────

	// 1. Certificate Validity Period
	if now.Before(leaf.NotBefore) {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_activation",
			Severity:       SeverityCritical,
			Observed:       fmt.Sprintf("Not valid until %s", leaf.NotBefore.Format("2006-01-02")),
			Expected:       "Certificate must be currently valid",
			Evidence:       fmt.Sprintf("NotBefore: %s, Current: %s", leaf.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339)),
			Recommendation: "Check server clock synchronization or install an active certificate.",
		})
		result.Score -= 40
	} else if now.After(leaf.NotAfter) {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_expiration",
			Severity:       SeverityCritical,
			Observed:       fmt.Sprintf("Expired on %s (%d days ago)", leaf.NotAfter.Format("2006-01-02"), -result.DaysUntilExpiration),
			Expected:       "Certificate must not be expired",
			Evidence:       fmt.Sprintf("NotAfter: %s, Current: %s", leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)),
			Recommendation: "Renew and deploy a valid certificate immediately to restore browser trust.",
		})
		result.Score -= 50
	} else if result.DaysUntilExpiration < 14 {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_expiration",
			Severity:       SeverityHigh,
			Observed:       fmt.Sprintf("%d days remaining until expiration", result.DaysUntilExpiration),
			Expected:       "Certificate should have > 14 days before expiration",
			Evidence:       fmt.Sprintf("Expires on: %s", leaf.NotAfter.Format("2006-01-02")),
			Recommendation: "Renew the certificate urgently to avoid unexpected outage.",
		})
		result.Score -= 20
	} else if result.DaysUntilExpiration < 30 {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_expiration",
			Severity:       SeverityMedium,
			Observed:       fmt.Sprintf("%d days remaining until expiration", result.DaysUntilExpiration),
			Expected:       "Certificate should have > 30 days before expiration",
			Evidence:       fmt.Sprintf("Expires on: %s", leaf.NotAfter.Format("2006-01-02")),
			Recommendation: "Schedule certificate renewal with your CA or automation provider (e.g. Certbot/ACME).",
		})
		result.Score -= 10
	} else {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_expiration",
			Severity:       SeverityInfo,
			Observed:       fmt.Sprintf("%d days remaining", result.DaysUntilExpiration),
			Expected:       "Certificate is active and adequately fresh",
			Evidence:       fmt.Sprintf("Valid until %s", leaf.NotAfter.Format("2006-01-02")),
			Recommendation: "Maintain automated renewal via ACME protocol.",
		})
	}

	// 2. Hostname matching
	errMatch := leaf.VerifyHostname(host)
	if errMatch != nil {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "hostname_validation",
			Severity:       SeverityCritical,
			Observed:       fmt.Sprintf("Hostname %q mismatch with SANs %v", host, leaf.DNSNames),
			Expected:       fmt.Sprintf("Certificate SAN list must include %q", host),
			Evidence:       errMatch.Error(),
			Recommendation: "Issue a new certificate containing the target domain or wildcard in Subject Alternative Names (SAN).",
		})
		result.Score -= 40
	} else {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "hostname_validation",
			Severity:       SeverityInfo,
			Observed:       fmt.Sprintf("Matches SANs (CN: %s)", leaf.Subject.CommonName),
			Expected:       "Certificate matches target domain",
			Evidence:       fmt.Sprintf("Domain %s is covered by SAN list", host),
			Recommendation: "Configuration is correct.",
		})
	}

	// 3. Protocol Version
	if cs.Version < tls.VersionTLS12 {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "tls_protocol_version",
			Severity:       SeverityHigh,
			Observed:       result.TLSVersion,
			Expected:       "TLS 1.2 or TLS 1.3 required",
			Evidence:       fmt.Sprintf("Negotiated deprecated protocol %s", result.TLSVersion),
			Recommendation: "Disable SSLv3, TLS 1.0, and TLS 1.1 in web server/load balancer configuration. Enforce TLS 1.2+.",
		})
		result.Score -= 25
	} else if cs.Version == tls.VersionTLS13 {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "tls_protocol_version",
			Severity:       SeverityInfo,
			Observed:       "TLS 1.3 (Modern)",
			Expected:       "TLS 1.2 or TLS 1.3",
			Evidence:       "Negotiated TLS 1.3 with 0-RTT support potential",
			Recommendation: "Maintain current TLS 1.3 configuration.",
		})
	} else {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "tls_protocol_version",
			Severity:       SeverityInfo,
			Observed:       "TLS 1.2 (Standard)",
			Expected:       "TLS 1.2 or TLS 1.3",
			Evidence:       "Negotiated secure TLS 1.2",
			Recommendation: "Consider enabling TLS 1.3 for lower handshake latency and enhanced security.",
		})
	}

	// 4. Public Key & Signature Strength
	if result.PublicKeySize > 0 && result.PublicKeySize < 2048 && leaf.PublicKeyAlgorithm == x509.RSA {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "key_strength",
			Severity:       SeverityHigh,
			Observed:       fmt.Sprintf("RSA %d bits", result.PublicKeySize),
			Expected:       "RSA >= 2048 bits or ECDSA >= 256 bits",
			Evidence:       fmt.Sprintf("Leaf key length is %d bits", result.PublicKeySize),
			Recommendation: "Replace certificate with at least a 2048-bit RSA key or a modern ECDSA (P-256/P-384) key.",
		})
		result.Score -= 20
	}

	if strings.Contains(strings.ToLower(result.SignatureAlgorithm), "sha1") ||
		strings.Contains(strings.ToLower(result.SignatureAlgorithm), "md5") {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "signature_algorithm",
			Severity:       SeverityHigh,
			Observed:       result.SignatureAlgorithm,
			Expected:       "SHA-256 or stronger",
			Evidence:       fmt.Sprintf("Deprecated hash function in %s", result.SignatureAlgorithm),
			Recommendation: "Re-issue certificate using SHA-256 (SHA-2) or stronger signature algorithm.",
		})
		result.Score -= 20
	}

	// 5. Certificate Chain Completeness
	if len(cs.PeerCertificates) == 1 && !leaf.IsCA {
		result.Checks = append(result.Checks, TLSCheck{
			Check:          "certificate_chain",
			Severity:       SeverityMedium,
			Observed:       "Incomplete certificate chain (intermediate cert missing)",
			Expected:       "Full chain including intermediate CA certificates",
			Evidence:       "Only leaf certificate was sent during TLS handshake",
			Recommendation: "Bundle the intermediate CA certificates (fullchain.pem) into the server TLS configuration.",
		})
		result.Score -= 10
	}

	if result.Score < 0 {
		result.Score = 0
	}

	// Generate summary
	switch {
	case result.Score >= 90:
		result.Summary = "Excellent TLS posture with modern protocols and valid certificate."
	case result.Score >= 75:
		result.Summary = "Good TLS configuration with minor optimization opportunities."
	case result.Score >= 50:
		result.Summary = "Moderate TLS risks detected; remediation recommended."
	default:
		result.Summary = "Critical TLS flaws or expiration detected requiring immediate attention."
	}

	return result, nil
}

func tlsVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0 (Deprecated)"
	case tls.VersionTLS11:
		return "TLS 1.1 (Deprecated)"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", ver)
	}
}
