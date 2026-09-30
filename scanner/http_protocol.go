package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AnalyzeHTTP inspects HTTP protocol support, security headers, cookies, and CORS.
func AnalyzeHTTP(ctx context.Context, targetURL string, timeout time.Duration) (*HTTPResult, *http.Response, []RedirectHop, error) {
	client := NewSafeHTTPClient(timeout, 5)

	var redirects []RedirectHop

	// Hook into redirect tracker
	priorURL := targetURL
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return ErrTooManyRedirects
		}
		// Record hop
		redirects = append(redirects, RedirectHop{
			FromURL:    priorURL,
			ToURL:      req.URL.String(),
			StatusCode: http.StatusFound, // default redirect
		})
		priorURL = req.URL.String()

		// Validate SSRF for redirect
		_, _, err := ValidateTargetURL(req.URL.String())
		if err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 VortexDNS-Scanner/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Origin", "https://vortexdns-probe.internal") // Safe origin probe for CORS evaluation

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, redirects, fmt.Errorf("http request failed: %w", err)
	}

	result := &HTTPResult{
		NegotiatedProtocol: resp.Proto,
		SupportedProtocols: []string{"HTTP/1.1"},
		ResponseProtocol:   resp.Proto,
		Redirects:          redirects,
		Compression:        resp.Header.Get("Content-Encoding"),
		ContentEncoding:    resp.Header.Get("Content-Type"),
		AltSvc:             resp.Header.Get("Alt-Svc"),
		SecurityHeaders:    make(map[string]HeaderAnalysis),
		Cookies:            []CookieAnalysis{},
		CORS:               CORSAnalysis{},
	}

	if resp.ProtoMajor == 2 {
		result.SupportedProtocols = append(result.SupportedProtocols, "HTTP/2")
	}

	// Inspect Alt-Svc for HTTP/3 / QUIC availability
	if result.AltSvc != "" {
		altLower := strings.ToLower(result.AltSvc)
		if strings.Contains(altLower, "h3") || strings.Contains(altLower, "quic") {
			result.SupportedProtocols = append(result.SupportedProtocols, "HTTP/3", "QUIC")
		}
	}

	// ── SECURITY HEADERS ANALYSIS ─────────────────────────────
	result.SecurityHeaders["Strict-Transport-Security"] = analyzeHSTS(resp.Header.Get("Strict-Transport-Security"), targetURL)
	result.SecurityHeaders["Content-Security-Policy"] = analyzeCSP(resp.Header.Get("Content-Security-Policy"))
	result.SecurityHeaders["X-Content-Type-Options"] = analyzeXCTO(resp.Header.Get("X-Content-Type-Options"))
	result.SecurityHeaders["Referrer-Policy"] = analyzeReferrerPolicy(resp.Header.Get("Referrer-Policy"))
	result.SecurityHeaders["Permissions-Policy"] = analyzePermissionsPolicy(resp.Header.Get("Permissions-Policy"))
	result.SecurityHeaders["Cross-Origin-Opener-Policy"] = analyzeCOOP(resp.Header.Get("Cross-Origin-Opener-Policy"))
	result.SecurityHeaders["Cross-Origin-Resource-Policy"] = analyzeCORP(resp.Header.Get("Cross-Origin-Resource-Policy"))
	result.SecurityHeaders["Cross-Origin-Embedder-Policy"] = analyzeCOEP(resp.Header.Get("Cross-Origin-Embedder-Policy"))

	// ── COOKIE ATTRIBUTES ANALYSIS ────────────────────────────
	for _, cookie := range resp.Cookies() {
		analysis := CookieAnalysis{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSiteString(cookie.SameSite),
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Issues:   []string{},
		}

		if !cookie.Secure && strings.HasPrefix(targetURL, "https://") {
			analysis.Issues = append(analysis.Issues, "Missing Secure flag on HTTPS site")
		}
		if !cookie.HttpOnly {
			analysis.Issues = append(analysis.Issues, "Missing HttpOnly flag (accessible to JavaScript document.cookie)")
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			analysis.Issues = append(analysis.Issues, "SameSite=None without Secure flag will be rejected by modern browsers")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			analysis.Issues = append(analysis.Issues, "SameSite attribute not explicitly defined (relies on browser default)")
		}

		result.Cookies = append(result.Cookies, analysis)
	}

	// ── CORS ANALYSIS ─────────────────────────────────────────
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	acex := resp.Header.Get("Access-Control-Expose-Headers")
	acma := resp.Header.Get("Access-Control-Max-Age")

	result.CORS = CORSAnalysis{
		AllowOrigin:             acao,
		AllowCredentials:        strings.EqualFold(acac, "true"),
		ExposedHeaders:          acex,
		PreflightMaxAge:         acma,
		OriginReflected:         acao == "https://vortexdns-probe.internal",
		WildcardWithCredentials: acao == "*" && strings.EqualFold(acac, "true"),
	}

	if result.CORS.WildcardWithCredentials {
		result.CORS.RiskDescription = "Critical misconfiguration: Access-Control-Allow-Origin '*' combined with Allow-Credentials true is invalid and unsafe."
	} else if result.CORS.OriginReflected && result.CORS.AllowCredentials {
		result.CORS.RiskDescription = "High risk: Arbitrary origin reflection with Allow-Credentials allows authenticated cross-origin data extraction."
	} else if acao == "*" {
		result.CORS.RiskDescription = "Permissive wildcard: Public resource allows reading by any external web origin."
	} else if acao != "" {
		result.CORS.RiskDescription = "Explicit CORS configuration applied."
	} else {
		result.CORS.RiskDescription = "Standard Same-Origin Policy applies (no public CORS header returned)."
	}

	return result, resp, redirects, nil
}

func sameSiteString(mode http.SameSite) string {
	switch mode {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default (Unspecified)"
	}
}

func analyzeHSTS(val, targetURL string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Strict-Transport-Security", Value: val, Present: val != ""}
	if !strings.HasPrefix(targetURL, "https://") {
		ha.Severity = SeverityInfo
		ha.Issue = "HSTS is not applicable over plaintext HTTP"
		ha.Recommendation = "Migrate website to HTTPS and enforce HSTS."
		return ha
	}
	if !ha.Present {
		ha.Severity = SeverityMedium
		ha.Issue = "Missing Strict-Transport-Security header"
		ha.Recommendation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to prevent SSL stripping attacks."
		return ha
	}
	ha.Severity = SeverityInfo
	if !strings.Contains(strings.ToLower(val), "includesubdomains") {
		ha.Severity = SeverityLow
		ha.Issue = "HSTS does not specify includeSubDomains"
		ha.Recommendation = "Add 'includeSubDomains' to protect subdomains against plaintext downgrade."
	}
	return ha
}

func analyzeCSP(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Content-Security-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityMedium
		ha.Issue = "Missing Content-Security-Policy header"
		ha.Recommendation = "Implement a strict Content-Security-Policy (CSP) to mitigate Cross-Site Scripting (XSS) and data injection."
		return ha
	}
	valLower := strings.ToLower(val)
	if strings.Contains(valLower, "'unsafe-inline'") || strings.Contains(valLower, "'unsafe-eval'") {
		ha.Severity = SeverityLow
		ha.Issue = "CSP contains 'unsafe-inline' or 'unsafe-eval'"
		ha.Recommendation = "Refactor inline scripts and eval usages; use cryptographic nonces or hashes instead."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzeXCTO(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "X-Content-Type-Options", Value: val, Present: val != ""}
	if !ha.Present || !strings.EqualFold(strings.TrimSpace(val), "nosniff") {
		ha.Severity = SeverityLow
		ha.Issue = "Missing or improper X-Content-Type-Options"
		ha.Recommendation = "Set 'X-Content-Type-Options: nosniff' to prevent MIME-type confusion attacks."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzeReferrerPolicy(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Referrer-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityLow
		ha.Issue = "Missing Referrer-Policy header"
		ha.Recommendation = "Set 'Referrer-Policy: strict-origin-when-cross-origin' to prevent URL parameter leakage in Referer headers."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzePermissionsPolicy(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Permissions-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityLow
		ha.Issue = "Missing Permissions-Policy header"
		ha.Recommendation = "Define 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to restrict browser APIs."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzeCOOP(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Cross-Origin-Opener-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityInfo
		ha.Issue = "COOP not specified"
		ha.Recommendation = "Consider setting 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing contexts."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzeCORP(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Cross-Origin-Resource-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityInfo
		ha.Issue = "CORP not specified"
		ha.Recommendation = "Consider setting 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' to protect resources from being embedded cross-origin."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}

func analyzeCOEP(val string) HeaderAnalysis {
	ha := HeaderAnalysis{Header: "Cross-Origin-Embedder-Policy", Value: val, Present: val != ""}
	if !ha.Present {
		ha.Severity = SeverityInfo
		ha.Issue = "COEP not specified"
		ha.Recommendation = "Consider setting 'Cross-Origin-Embedder-Policy: require-corp' if using cross-origin isolated features."
		return ha
	}
	ha.Severity = SeverityInfo
	return ha
}
