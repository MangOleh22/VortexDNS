package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// MeasureLighthouse runs Lighthouse CLI if available in the environment; otherwise marks status: unavailable.
func MeasureLighthouse(ctx context.Context, targetURL string, timeout time.Duration) *LighthouseResult {
	// Check if lighthouse CLI is installed
	lhPath, err := exec.LookPath("lighthouse")
	if err != nil {
		// Try npx lighthouse without interactive prompts
		lhPath = ""
	}

	result := &LighthouseResult{
		Status:  "unavailable",
		Engine:  "None (Lighthouse CLI not detected in system PATH)",
		Metrics: LighthouseMetrics{},
	}

	if lhPath == "" {
		return result
	}

	// Prepare bounded command
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Flags for safe, headless, headless-quiet output
	cmd := exec.CommandContext(ctxTimeout, lhPath,
		targetURL,
		"--output=json",
		"--output-path=stdout",
		"--chrome-flags=--headless --no-sandbox --disable-gpu --disable-dev-shm-usage",
		"--quiet",
		"--max-wait-for-load=15000",
		"--only-categories=performance,accessibility,best-practices,seo,pwa",
	)

	out, err := cmd.Output()
	if err != nil {
		result.Status = "unavailable"
		result.Engine = fmt.Sprintf("Lighthouse execution error: %v", err)
		return result
	}

	// Parse structured Lighthouse output
	var lhReport struct {
		Categories struct {
			Performance struct {
				Score *float64 `json:"score"`
			} `json:"performance"`
			Accessibility struct {
				Score *float64 `json:"score"`
			} `json:"accessibility"`
			BestPractices struct {
				Score *float64 `json:"score"`
			} `json:"best-practices"`
			SEO struct {
				Score *float64 `json:"score"`
			} `json:"seo"`
			PWA struct {
				Score *float64 `json:"score"`
			} `json:"pwa"`
		} `json:"categories"`
		Audits map[string]struct {
			NumericValue *float64 `json:"numericValue"`
		} `json:"audits"`
	}

	if err := json.Unmarshal(out, &lhReport); err != nil {
		result.Status = "unavailable"
		result.Engine = "Failed to parse Lighthouse JSON output"
		return result
	}

	result.Status = "available"
	result.Engine = "Google Lighthouse CLI (Headless Chromium)"

	if lhReport.Categories.Performance.Score != nil {
		score := int(*lhReport.Categories.Performance.Score * 100)
		result.Performance = &score
	}
	if lhReport.Categories.Accessibility.Score != nil {
		score := int(*lhReport.Categories.Accessibility.Score * 100)
		result.Accessibility = &score
	}
	if lhReport.Categories.BestPractices.Score != nil {
		score := int(*lhReport.Categories.BestPractices.Score * 100)
		result.BestPractices = &score
	}
	if lhReport.Categories.SEO.Score != nil {
		score := int(*lhReport.Categories.SEO.Score * 100)
		result.SEO = &score
	}
	if lhReport.Categories.PWA.Score != nil {
		score := int(*lhReport.Categories.PWA.Score * 100)
		result.PWA = &score
	}

	// Core Web Vitals extraction
	if fcp, ok := lhReport.Audits["first-contentful-paint"]; ok {
		result.Metrics.FCPMs = fcp.NumericValue
	}
	if lcp, ok := lhReport.Audits["largest-contentful-paint"]; ok {
		result.Metrics.LCPMs = lcp.NumericValue
	}
	if tbt, ok := lhReport.Audits["total-blocking-time"]; ok {
		result.Metrics.TBTMs = tbt.NumericValue
	}
	if cls, ok := lhReport.Audits["cumulative-layout-shift"]; ok {
		result.Metrics.CLS = cls.NumericValue
	}
	if si, ok := lhReport.Audits["speed-index"]; ok {
		result.Metrics.SpeedIndexMs = si.NumericValue
	}
	if tti, ok := lhReport.Audits["interactive"]; ok {
		result.Metrics.TTIMs = tti.NumericValue
	}

	return result
}

// IsLighthouseAvailable checks if Lighthouse CLI is discoverable in PATH.
func IsLighthouseAvailable() bool {
	_, err := exec.LookPath("lighthouse")
	return err == nil
}

// FormatLighthouseScore formats a score or placeholder.
func FormatLighthouseScore(score *int) string {
	if score == nil {
		return "N/A"
	}
	return fmt.Sprintf("%d", *score)
}

// FormatMetricMS formats a millisecond metric.
func FormatMetricMS(ms *float64) string {
	if ms == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.1f ms", *ms)
}
