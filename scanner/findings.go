package scanner

import (
	"fmt"
)

// GenerateFindings synthesizes raw scan results into typed security, performance, and risk mitigations.
func GenerateFindings(
	targetHost string,
	tlsResult *TLSResult,
	httpResult *HTTPResult,
	aiReport AIReport,
	pwaResult *PWAFinding,
	crawlResult *CrawlResult,
) ([]SecurityFinding, []PerformanceFinding, []MitigationGroup, ReportSummary) {
	securityFindings := make([]SecurityFinding, 0)
	performanceFindings := make([]PerformanceFinding, 0)

	// 1. Ingest AI Security Findings
	securityFindings = append(securityFindings, aiReport.SecurityFindings...)

	// 2. Ingest TLS Findings
	if tlsResult != nil {
		for _, check := range tlsResult.Checks {
			if check.Severity == SeverityCritical || check.Severity == SeverityHigh || check.Severity == SeverityMedium {
				secID := fmt.Sprintf("TLS-%03d", len(securityFindings)+1)
				group := "Medium-term"
				priority := "P2"
				effort := "Small"
				switch check.Severity {
				case SeverityCritical:
					group = "Immediate"
					priority = "P0"
				case SeverityHigh:
					group = "Short-term"
					priority = "P1"
				}

				securityFindings = append(securityFindings, SecurityFinding{
					ID:         secID,
					Category:   "tls",
					Severity:   check.Severity,
					Confidence: 1.0,
					Title:      fmt.Sprintf("TLS Configuration: %s", check.Check),
					Description: fmt.Sprintf("Observed %s. Expected: %s.", check.Observed, check.Expected),
					Evidence: map[string]interface{}{
						"check":    check.Check,
						"observed": check.Observed,
						"evidence": check.Evidence,
					},
					Impact:         "Service availability degradation or susceptibility to network eavesdropping and certificate warnings.",
					Likelihood:     "High",
					AffectedAsset:  targetHost,
					Effort:         effort,
					Priority:       priority,
					MitigationTime: group,
					Mitigation: RemediationDetail{
						Action:                 check.Recommendation,
						TechnicalFix:           fmt.Sprintf("Update TLS certificate or cipher suite configuration for %s.", targetHost),
						ExpectedResult:         "Subsequent TLS handshakes pass with zero errors.",
						Verification:           "Re-run TLS check using vortexdns scanner and confirm validity.",
						ImplementationExample: fmt.Sprintf("# Verify with OpenSSL:\nopenssl s_client -connect %s:443 -servername %s", targetHost, targetHost),
					},
				})
			}
		}
	}

	// 3. Ingest HTTP Security Headers Findings
	if httpResult != nil {
		for hName, hAnalysis := range httpResult.SecurityHeaders {
			if hAnalysis.Severity == SeverityMedium || hAnalysis.Severity == SeverityHigh {
				secID := fmt.Sprintf("HDR-%03d", len(securityFindings)+1)
				securityFindings = append(securityFindings, SecurityFinding{
					ID:         secID,
					Category:   "http_security",
					Severity:   hAnalysis.Severity,
					Confidence: 1.0,
					Title:      fmt.Sprintf("Missing or Weak Header: %s", hName),
					Description: fmt.Sprintf("The server response did not enforce a secure %s header: %s", hName, hAnalysis.Issue),
					Evidence: map[string]interface{}{
						"header":  hName,
						"present": hAnalysis.Present,
						"value":   hAnalysis.Value,
					},
					Impact:         "Weakened browser defenses against XSS, clickjacking, MIME confusion, or SSL stripping.",
					Likelihood:     "Medium",
					AffectedAsset:  targetHost,
					Effort:         "Small",
					Priority:       "P2",
					MitigationTime: "Short-term",
					Mitigation: RemediationDetail{
						Action:                 hAnalysis.Recommendation,
						TechnicalFix:           fmt.Sprintf("Configure reverse proxy / web server to inject %s header.", hName),
						ExpectedResult:         fmt.Sprintf("%s is returned on all public endpoints.", hName),
						Verification:           fmt.Sprintf("curl -I https://%s | grep -i %s", targetHost, hName),
						ImplementationExample: fmt.Sprintf("# Nginx:\nadd_header %s \"...\";", hName),
					},
				})
			}
		}

		// CORS Findings
		if httpResult.CORS.WildcardWithCredentials || (httpResult.CORS.OriginReflected && httpResult.CORS.AllowCredentials) {
			secID := fmt.Sprintf("CORS-%03d", len(securityFindings)+1)
			securityFindings = append(securityFindings, SecurityFinding{
				ID:         secID,
				Category:   "cors",
				Severity:   SeverityHigh,
				Confidence: 0.95,
				Title:      "Insecure CORS Configuration with Credentials",
				Description: httpResult.CORS.RiskDescription,
				Evidence: map[string]interface{}{
					"allow_origin":      httpResult.CORS.AllowOrigin,
					"allow_credentials": httpResult.CORS.AllowCredentials,
				},
				Impact:         "Malicious third-party websites can issue authenticated cross-origin requests and read sensitive responses.",
				Likelihood:     "High",
				AffectedAsset:  targetHost,
				Effort:         "Small",
				Priority:       "P1",
				MitigationTime: "Immediate",
				Mitigation: RemediationDetail{
					Action:                 "Restrict Access-Control-Allow-Origin to trusted explicit origins when credentials are enabled.",
					TechnicalFix:           "Never reflect arbitrary request origins blindly in Access-Control-Allow-Origin with credentials: true.",
					ExpectedResult:         "Only explicitly whitelisted domains receive CORS approval with credentials.",
					Verification:           "Send OPTIONS preflight with Origin: https://evil.com and confirm rejection.",
					ImplementationExample: "// Express:\napp.use(cors({ origin: ['https://trusted.app.com'], credentials: true }));",
				},
			})
		}

		// Cookie Findings
		for _, cookie := range httpResult.Cookies {
			if len(cookie.Issues) > 0 {
				for _, issue := range cookie.Issues {
					secID := fmt.Sprintf("CK-%03d", len(securityFindings)+1)
					securityFindings = append(securityFindings, SecurityFinding{
						ID:         secID,
						Category:   "cookie_security",
						Severity:   SeverityLow,
						Confidence: 1.0,
						Title:      fmt.Sprintf("Insecure Cookie Configuration: %s", cookie.Name),
						Description: issue,
						Evidence: map[string]interface{}{
							"cookie":    cookie.Name,
							"secure":    cookie.Secure,
							"http_only": cookie.HttpOnly,
							"same_site": cookie.SameSite,
						},
						Impact:         "Cookie could potentially be read via JavaScript or transmitted over unencrypted connections.",
						Likelihood:     "Low",
						AffectedAsset:  cookie.Name,
						Effort:         "Small",
						Priority:       "P3",
						MitigationTime: "Medium-term",
						Mitigation: RemediationDetail{
							Action:                 "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on this cookie.",
							TechnicalFix:           fmt.Sprintf("Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax", cookie.Name),
							ExpectedResult:         "Cookie flags are properly enforced by modern browsers.",
							Verification:           "Inspect response headers in browser DevTools Application > Cookies.",
						},
					})
				}
			}
		}
	}

	// 4. Performance Findings
	if crawlResult != nil {
		for _, req := range crawlResult.Requests {
			if req.DurationMs > 1000 {
				performanceFindings = append(performanceFindings, PerformanceFinding{
					ID:             fmt.Sprintf("PERF-%03d", len(performanceFindings)+1),
					Metric:         "High Request Latency",
					ObservedValue:  fmt.Sprintf("%d ms", req.DurationMs),
					Threshold:      "1000 ms",
					Severity:       SeverityMedium,
					Impact:         "Slow server response degrades user experience and Core Web Vitals (LCP).",
					Recommendation: fmt.Sprintf("Investigate backend execution or asset delivery for %s. Utilize CDN edge caching.", req.URL),
				})
			}
			if req.EncodedSize > 1024*1024 && req.ResourceType == "script" {
				performanceFindings = append(performanceFindings, PerformanceFinding{
					ID:             fmt.Sprintf("PERF-%03d", len(performanceFindings)+1),
					Metric:         "Oversized JavaScript Asset",
					ObservedValue:  fmt.Sprintf("%.2f MB", float64(req.EncodedSize)/(1024*1024)),
					Threshold:      "1.0 MB",
					Severity:       SeverityMedium,
					Impact:         "Large script bundles prolong parse/compile time, increasing Total Blocking Time (TBT).",
					Recommendation: "Implement code splitting, tree shaking, and modern compression (Brotli/Zstandard).",
				})
			}
		}
	}

	// 5. Structure Prioritized Mitigations
	groupsMap := map[string][]SecurityFinding{
		"Immediate":   {},
		"Short-term":  {},
		"Medium-term": {},
		"Strategic":   {},
	}

	critCount := 0
	highCount := 0
	medCount := 0
	lowCount := 0
	infoCount := 0

	for _, sf := range securityFindings {
		switch sf.Severity {
		case SeverityCritical:
			critCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			medCount++
		case SeverityLow:
			lowCount++
		default:
			infoCount++
		}

		timeframe := sf.MitigationTime
		if timeframe == "" {
			timeframe = "Medium-term"
		}
		groupsMap[timeframe] = append(groupsMap[timeframe], sf)
	}

	orderedGroups := []MitigationGroup{
		{Timeframe: "Immediate", Items: groupsMap["Immediate"]},
		{Timeframe: "Short-term", Items: groupsMap["Short-term"]},
		{Timeframe: "Medium-term", Items: groupsMap["Medium-term"]},
		{Timeframe: "Strategic", Items: groupsMap["Strategic"]},
	}

	// 6. Report Summary
	health := "Healthy"
	if critCount > 0 {
		health = "Critical Risks Present"
	} else if highCount > 0 {
		health = "Attention Needed"
	} else if medCount > 0 {
		health = "Moderate Optimization Potential"
	}

	tlsPosture := "Secure"
	if tlsResult != nil {
		if tlsResult.Score < 60 {
			tlsPosture = "Degraded"
		} else if tlsResult.Score < 85 {
			tlsPosture = "Acceptable"
		}
	}

	perfCondition := "Optimal"
	if len(performanceFindings) > 3 {
		perfCondition = "Degraded"
	} else if len(performanceFindings) > 0 {
		perfCondition = "Good"
	}

	summary := ReportSummary{
		WebsiteHealth:            health,
		PerformanceCondition:     perfCondition,
		TLSPosture:               tlsPosture,
		SecurityPosture:          fmt.Sprintf("%d Critical, %d High, %d Medium findings", critCount, highCount, medCount),
		AINativeStatus:           aiReport.Classification,
		AIConfidence:             aiReport.Confidence,
		CriticalCount:            critCount,
		HighCount:                highCount,
		MediumCount:              medCount,
		LowCount:                 lowCount,
		InfoCount:                infoCount,
		ImmediateMitigationCount: len(groupsMap["Immediate"]),
	}

	return securityFindings, performanceFindings, orderedGroups, summary
}
