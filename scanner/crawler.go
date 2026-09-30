package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CrawlResult encapsulates data collected during bounded site crawling.
type CrawlResult struct {
	PagesDiscovered int
	PagesScanned    int
	PagesSkipped    int
	RequestsTotal   int
	BytesReceived   int64
	Requests        []NetworkRequest
	ScriptURLs      []string
	ScriptBodies    map[string]string
	Endpoints       []string
	HasLLMSTxt      bool
	HTMLBodies      map[string]string
	Waterfall       []WaterfallEntry
}

// BoundedCrawler performs safe, limited, rate-controlled page and asset discovery.
type BoundedCrawler struct {
	config     ScanConfig
	client     *http.Client
	baseURL    *url.URL
	targetHost string
}

// NewBoundedCrawler creates a crawler configured with SSRF-safe client and bounds.
func NewBoundedCrawler(cfg ScanConfig, targetURL *url.URL) *BoundedCrawler {
	client := NewSafeHTTPClient(time.Duration(cfg.RequestTimeoutSeconds)*time.Second, cfg.MaxRedirects)
	return &BoundedCrawler{
		config:     cfg,
		client:     client,
		baseURL:    targetURL,
		targetHost: targetURL.Host,
	}
}

// Crawl executes the bounded crawling pipeline.
func (c *BoundedCrawler) Crawl(ctx context.Context, onProgress func(discovered, scanned, skipped int, stage string)) (*CrawlResult, error) {
	result := &CrawlResult{
		ScriptBodies: make(map[string]string),
		HTMLBodies:   make(map[string]string),
		Requests:     make([]NetworkRequest, 0),
		Waterfall:    make([]WaterfallEntry, 0),
	}

	queue := make([]string, 0)
	visited := make(map[string]bool)
	depthMap := make(map[string]int)

	initialURL := c.baseURL.String()
	queue = append(queue, initialURL)
	depthMap[initialURL] = 0
	result.PagesDiscovered = 1

	// Check robots.txt and sitemap.xml for route discovery
	c.checkRobotsAndSitemap(ctx, result)

	// Check llms.txt standard
	c.checkLLMSTxt(ctx, result)

	// Bounded concurrency worker pool
	sem := make(chan struct{}, c.config.MaxConcurrency)
	var mu sync.Mutex

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if result.PagesScanned >= c.config.MaxPages {
			result.PagesSkipped += len(queue)
			break
		}

		currentURL := queue[0]
		queue = queue[1:]

		mu.Lock()
		if visited[currentURL] {
			mu.Unlock()
			continue
		}
		visited[currentURL] = true
		currDepth := depthMap[currentURL]
		mu.Unlock()

		if currDepth > c.config.MaxDepth {
			result.PagesSkipped++
			continue
		}

		sem <- struct{}{}
		startReq := time.Now()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			<-sem
			result.PagesSkipped++
			continue
		}
		req.Header.Set("User-Agent", c.config.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := c.client.Do(req)
		elapsed := time.Since(startReq).Milliseconds()
		<-sem

		if err != nil {
			result.PagesSkipped++
			continue
		}

		// Read response body up to 2MB limit per page
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()

		result.PagesScanned++
		result.RequestsTotal++
		atomic.AddInt64(&result.BytesReceived, int64(len(bodyBytes)))

		u, _ := url.Parse(currentURL)
		reqHost := ""
		if u != nil {
			reqHost = u.Host
		}

		// Log request metadata
		netReq := NetworkRequest{
			ID:           fmt.Sprintf("req-%04d", result.RequestsTotal),
			URL:          currentURL,
			Host:         reqHost,
			Method:       "GET",
			ResourceType: "document",
			Status:       resp.StatusCode,
			Protocol:     resp.Proto,
			DurationMs:   elapsed,
			EncodedSize:  int64(len(bodyBytes)),
			DecodedSize:  int64(len(bodyBytes)),
			CacheStatus:  resp.Header.Get("CF-Cache-Status"),
			IsThirdParty: reqHost != c.targetHost,
			Category:     "document",
		}
		result.Requests = append(result.Requests, netReq)

		if len(result.Waterfall) < 15 {
			result.Waterfall = append(result.Waterfall, WaterfallEntry{
				URL:        currentURL,
				TTFBMs:     elapsed / 2,
				DownloadMs: elapsed / 2,
				TotalMs:    elapsed,
			})
		}

		htmlContent := string(bodyBytes)
		result.HTMLBodies[currentURL] = htmlContent

		// Discover links and script assets
		discoveredLinks, scripts := c.extractLinksAndScripts(c.baseURL, htmlContent)
		for _, s := range scripts {
			result.ScriptURLs = append(result.ScriptURLs, s)
		}

		// Download top public script assets boundedly for Tech & AI detection
		c.sampleScripts(ctx, scripts, result)

		// Queue unvisited same-origin links
		mu.Lock()
		for _, link := range discoveredLinks {
			if !visited[link] && depthMap[link] == 0 {
				depthMap[link] = currDepth + 1
				queue = append(queue, link)
				result.PagesDiscovered++
			}
		}
		mu.Unlock()

		if onProgress != nil {
			onProgress(result.PagesDiscovered, result.PagesScanned, result.PagesSkipped, fmt.Sprintf("Inspecting %s", currentURL))
		}
	}

	return result, nil
}

func (c *BoundedCrawler) checkRobotsAndSitemap(ctx context.Context, res *CrawlResult) {
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", c.baseURL.Scheme, c.baseURL.Host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", c.config.UserAgent)
		resp, err := c.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				res.RequestsTotal++
				res.BytesReceived += int64(len(body))
				// Discover routes in Disallow / Allow / Sitemap
				lines := strings.Split(string(body), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
						parts := strings.SplitN(line, ":", 2)
						if len(parts) > 1 {
							res.Endpoints = append(res.Endpoints, strings.TrimSpace(parts[1]))
						}
					}
				}
			}
		}
	}
}

func (c *BoundedCrawler) checkLLMSTxt(ctx context.Context, res *CrawlResult) {
	llmsURL := fmt.Sprintf("%s://%s/llms.txt", c.baseURL.Scheme, c.baseURL.Host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, llmsURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", c.config.UserAgent)
		resp, err := c.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				res.HasLLMSTxt = true
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
				res.RequestsTotal++
				res.BytesReceived += int64(len(body))
				res.Endpoints = append(res.Endpoints, llmsURL)
			}
		}
	}
}

func (c *BoundedCrawler) extractLinksAndScripts(base *url.URL, html string) ([]string, []string) {
	links := make([]string, 0)
	scripts := make([]string, 0)

	linkRe := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"'#\s]+)["']`)
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"'#\s]+)["']`)

	for _, m := range linkRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			resolved := resolveURL(base, m[1])
			parsed, err := url.Parse(resolved)
			// Only follow same-origin links
			if err == nil && parsed.Host == base.Host && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				cleanURL := strings.Split(resolved, "?")[0] // strip query parameters
				links = append(links, cleanURL)
			}
		}
	}

	for _, m := range scriptRe.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			resolved := resolveURL(base, m[1])
			scripts = append(scripts, resolved)
		}
	}

	return links, scripts
}

func (c *BoundedCrawler) sampleScripts(ctx context.Context, scriptURLs []string, res *CrawlResult) {
	// Sample up to 10 unique scripts to avoid overloading crawl budget
	sampled := 0
	for _, sURL := range scriptURLs {
		if sampled >= 10 {
			break
		}
		if res.ScriptBodies[sURL] != "" {
			continue
		}

		parsed, err := url.Parse(sURL)
		if err != nil {
			continue
		}

		// Don't crawl untrusted third parties for scripts if scheme isn't http/https
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}

		startReq := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.config.UserAgent)

		resp, err := c.client.Do(req)
		elapsed := time.Since(startReq).Milliseconds()
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB per script
		resp.Body.Close()

		res.RequestsTotal++
		res.BytesReceived += int64(len(body))
		res.ScriptBodies[sURL] = string(body)
		sampled++

		isTP := parsed.Host != c.targetHost
		cat := "script"
		if isTP {
			cat = categorizeThirdParty(parsed.Host)
		}

		res.Requests = append(res.Requests, NetworkRequest{
			ID:           fmt.Sprintf("req-%04d", res.RequestsTotal),
			URL:          sURL,
			Host:         parsed.Host,
			Method:       "GET",
			ResourceType: "script",
			Status:       resp.StatusCode,
			Protocol:     resp.Proto,
			DurationMs:   elapsed,
			EncodedSize:  int64(len(body)),
			DecodedSize:  int64(len(body)),
			IsThirdParty: isTP,
			Category:     cat,
		})
	}
}

func categorizeThirdParty(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "analytics") || strings.Contains(h, "gtm"):
		return "Analytics"
	case strings.Contains(h, "font"):
		return "Fonts"
	case strings.Contains(h, "cdn") || strings.Contains(h, "cloudflare") || strings.Contains(h, "fastly"):
		return "CDN"
	case strings.Contains(h, "sentry") || strings.Contains(h, "datadog"):
		return "Monitoring"
	case strings.Contains(h, "stripe") || strings.Contains(h, "paypal"):
		return "Payments"
	case strings.Contains(h, "clerk") || strings.Contains(h, "auth0"):
		return "Authentication"
	case strings.Contains(h, "openai") || strings.Contains(h, "anthropic") || strings.Contains(h, "pinecone"):
		return "AI Provider"
	default:
		return "External Service"
	}
}
