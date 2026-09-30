package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ManifestJSON represents standard Web App Manifest properties.
type ManifestJSON struct {
	Name            string        `json:"name"`
	ShortName       string        `json:"short_name"`
	StartURL        string        `json:"start_url"`
	Display         string        `json:"display"`
	ThemeColor      string        `json:"theme_color"`
	BackgroundColor string        `json:"background_color"`
	Icons           []ManifestIcon`json:"icons"`
}

// ManifestIcon represents an icon in manifest.json.
type ManifestIcon struct {
	Src   string `json:"src"`
	Sizes string `json:"sizes"`
	Type  string `json:"type"`
}

// AnalyzePWA inspects HTML, manifest, and service worker indicators for Progressive Web App capabilities.
func AnalyzePWA(ctx context.Context, baseURL string, htmlBody string, timeout time.Duration) *PWAFinding {
	finding := &PWAFinding{
		Findings: []string{},
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return finding
	}

	// 1. Check for Manifest link in HTML
	manifestRe := regexp.MustCompile(`(?i)<link[^>]+rel=["']manifest["'][^>]*>`)
	hrefRe := regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

	manifestMatch := manifestRe.FindString(htmlBody)
	if manifestMatch != "" {
		finding.HasManifest = true
		if hrefMatch := hrefRe.FindStringSubmatch(manifestMatch); len(hrefMatch) > 1 {
			relHref := hrefMatch[1]
			absURL := resolveURL(base, relHref)
			finding.ManifestURL = absURL

			// Fetch manifest safely
			fetchManifest(ctx, absURL, finding, timeout)
		}
	} else {
		finding.Findings = append(finding.Findings, "Missing Web App Manifest (<link rel=\"manifest\">)")
	}

	// 2. Check for Service Worker registration in HTML or scripts
	swRe := regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\s*\(\s*["']([^"']+)["']`)
	if swMatch := swRe.FindStringSubmatch(htmlBody); len(swMatch) > 1 {
		finding.HasServiceWorker = true
		finding.ServiceWorkerURL = resolveURL(base, swMatch[1])
		finding.OfflineReady = true
	} else if strings.Contains(htmlBody, "serviceWorker") {
		finding.HasServiceWorker = true
		finding.OfflineReady = true
	}

	if !finding.HasServiceWorker {
		finding.Findings = append(finding.Findings, "No Service Worker registration detected (offline fallback unavailable)")
	}

	// 3. Check for Theme Color meta tag
	themeRe := regexp.MustCompile(`(?i)<meta[^>]+name=["']theme-color["'][^>]+content=["']([^"']+)["']`)
	if themeMatch := themeRe.FindStringSubmatch(htmlBody); len(themeMatch) > 1 {
		finding.ThemeColor = themeMatch[1]
	}

	// 4. Installability criteria
	if finding.HasManifest && finding.HasServiceWorker && finding.IconsCount > 0 &&
		(finding.DisplayMode == "standalone" || finding.DisplayMode == "fullscreen" || finding.DisplayMode == "minimal-ui") {
		finding.Installable = true
	}

	return finding
}

func fetchManifest(ctx context.Context, manifestURL string, finding *PWAFinding, timeout time.Duration) {
	client := NewSafeHTTPClient(timeout, 3)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		finding.Findings = append(finding.Findings, "Failed to create manifest request")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		finding.Findings = append(finding.Findings, "Could not load manifest: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		finding.Findings = append(finding.Findings, "Manifest returned non-200 HTTP status")
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB max
	if err != nil {
		return
	}

	var m ManifestJSON
	if err := json.Unmarshal(body, &m); err != nil {
		finding.Findings = append(finding.Findings, "Manifest is not valid JSON")
		return
	}

	finding.Name = m.Name
	finding.ShortName = m.ShortName
	finding.DisplayMode = m.Display
	finding.StartURL = m.StartURL
	if finding.ThemeColor == "" {
		finding.ThemeColor = m.ThemeColor
	}
	finding.BackgroundColor = m.BackgroundColor
	finding.IconsCount = len(m.Icons)

	if finding.IconsCount == 0 {
		finding.Findings = append(finding.Findings, "Manifest contains no icons")
	}
	if finding.ShortName == "" && finding.Name == "" {
		finding.Findings = append(finding.Findings, "Manifest is missing name and short_name")
	}
	if finding.StartURL == "" {
		finding.Findings = append(finding.Findings, "Manifest is missing start_url")
	}
}

func resolveURL(base *url.URL, relative string) string {
	rel, err := url.Parse(relative)
	if err != nil {
		return relative
	}
	return base.ResolveReference(rel).String()
}
