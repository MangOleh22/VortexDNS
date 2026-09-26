package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// TechSignature defines a pattern matcher for a technology.
type TechSignature struct {
	Name       string
	Category   string
	Website    string
	Headers    map[string]*regexp.Regexp
	HTML       []*regexp.Regexp
	ScriptURLs []*regexp.Regexp
	Meta       map[string]*regexp.Regexp
	Cookies    []*regexp.Regexp
	Confidence float64
}

// Built-in technology signatures
var techSignatures = []TechSignature{
	// Frontend Frameworks & Meta-Frameworks
	{
		Name:     "Next.js",
		Category: "Frontend Framework",
		Website:  "https://nextjs.org",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by":  regexp.MustCompile(`(?i)next\.js`),
			"x-nextjs-page": regexp.MustCompile(`.+`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`id="__next"`),
			regexp.MustCompile(`__NEXT_DATA__`),
		},
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`/_next/static/`),
		},
		Confidence: 0.97,
	},
	{
		Name:     "React",
		Category: "Frontend Framework",
		Website:  "https://react.dev",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`data-reactroot`),
			regexp.MustCompile(`data-reactid`),
			regexp.MustCompile(`_reactListening`),
		},
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`react(?:\.production|\.development)?(?:\.min)?\.js`),
			regexp.MustCompile(`react-dom(?:\.production|\.development)?(?:\.min)?\.js`),
		},
		Confidence: 0.92,
	},
	{
		Name:     "Vue.js",
		Category: "Frontend Framework",
		Website:  "https://vuejs.org",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`data-v-[a-f0-9]+`),
			regexp.MustCompile(`__vue_app__`),
		},
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js`),
		},
		Confidence: 0.93,
	},
	{
		Name:     "Nuxt",
		Category: "Frontend Framework",
		Website:  "https://nuxt.com",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`(?i)nuxt`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`id="__nuxt"`),
			regexp.MustCompile(`__NUXT__`),
		},
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`/_nuxt/`),
		},
		Confidence: 0.96,
	},
	{
		Name:     "Astro",
		Category: "Frontend Framework",
		Website:  "https://astro.build",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`data-astro-`),
			regexp.MustCompile(`<astro-island`),
		},
		Meta: map[string]*regexp.Regexp{
			"generator": regexp.MustCompile(`(?i)astro`),
		},
		Confidence: 0.95,
	},
	{
		Name:     "Svelte",
		Category: "Frontend Framework",
		Website:  "https://svelte.dev",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`class="svelte-[a-z0-9]+"`),
			regexp.MustCompile(`__svelte__`),
		},
		Confidence: 0.91,
	},
	{
		Name:     "Angular",
		Category: "Frontend Framework",
		Website:  "https://angular.dev",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`ng-version`),
			regexp.MustCompile(`ng-app`),
		},
		Confidence: 0.94,
	},

	// Backend Frameworks & Platforms
	{
		Name:     "Laravel",
		Category: "Backend Framework",
		Website:  "https://laravel.com",
		Headers: map[string]*regexp.Regexp{
			"set-cookie": regexp.MustCompile(`(?i)laravel_session`),
		},
		Cookies: []*regexp.Regexp{
			regexp.MustCompile(`(?i)laravel_session`),
			regexp.MustCompile(`(?i)XSRF-TOKEN`),
		},
		Confidence: 0.92,
	},
	{
		Name:     "Django",
		Category: "Backend Framework",
		Website:  "https://djangoproject.com",
		Cookies: []*regexp.Regexp{
			regexp.MustCompile(`(?i)csrftoken`),
			regexp.MustCompile(`(?i)django`),
		},
		Confidence: 0.85,
	},
	{
		Name:     "FastAPI",
		Category: "Backend Framework",
		Website:  "https://fastapi.tiangolo.com",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)uvicorn`),
		},
		Confidence: 0.88,
	},
	{
		Name:     "Express",
		Category: "Backend Framework",
		Website:  "https://expressjs.com",
		Headers: map[string]*regexp.Regexp{
			"x-powered-by": regexp.MustCompile(`(?i)express`),
		},
		Confidence: 0.95,
	},

	// Web Servers & Reverse Proxies
	{
		Name:     "Nginx",
		Category: "Web Server",
		Website:  "https://nginx.org",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)nginx`),
		},
		Confidence: 0.95,
	},
	{
		Name:     "Caddy",
		Category: "Web Server",
		Website:  "https://caddyserver.com",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)caddy`),
		},
		Confidence: 0.95,
	},
	{
		Name:     "Apache",
		Category: "Web Server",
		Website:  "https://httpd.apache.org",
		Headers: map[string]*regexp.Regexp{
			"server": regexp.MustCompile(`(?i)apache`),
		},
		Confidence: 0.95,
	},

	// CDNs & Cloud Providers
	{
		Name:     "Cloudflare",
		Category: "CDN",
		Website:  "https://cloudflare.com",
		Headers: map[string]*regexp.Regexp{
			"server":  regexp.MustCompile(`(?i)cloudflare`),
			"cf-ray":  regexp.MustCompile(`.+`),
			"cf-cache-status": regexp.MustCompile(`.+`),
		},
		Confidence: 0.99,
	},
	{
		Name:     "Vercel",
		Category: "Cloud Provider",
		Website:  "https://vercel.com",
		Headers: map[string]*regexp.Regexp{
			"x-vercel-id":    regexp.MustCompile(`.+`),
			"x-vercel-cache": regexp.MustCompile(`.+`),
			"server":         regexp.MustCompile(`(?i)vercel`),
		},
		Confidence: 0.99,
	},
	{
		Name:     "Netlify",
		Category: "Cloud Provider",
		Website:  "https://netlify.com",
		Headers: map[string]*regexp.Regexp{
			"x-nf-request-id": regexp.MustCompile(`.+`),
			"server":          regexp.MustCompile(`(?i)netlify`),
		},
		Confidence: 0.99,
	},
	{
		Name:     "Amazon CloudFront",
		Category: "CDN",
		Website:  "https://aws.amazon.com/cloudfront",
		Headers: map[string]*regexp.Regexp{
			"x-amz-cf-id":  regexp.MustCompile(`.+`),
			"x-amz-cf-pop": regexp.MustCompile(`.+`),
			"via":          regexp.MustCompile(`(?i)cloudfront`),
		},
		Confidence: 0.99,
	},

	// CMS
	{
		Name:     "WordPress",
		Category: "CMS",
		Website:  "https://wordpress.org",
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`/wp-content/`),
			regexp.MustCompile(`/wp-includes/`),
		},
		Meta: map[string]*regexp.Regexp{
			"generator": regexp.MustCompile(`(?i)wordpress`),
		},
		Confidence: 0.97,
	},
	{
		Name:     "Ghost",
		Category: "CMS",
		Website:  "https://ghost.org",
		Meta: map[string]*regexp.Regexp{
			"generator": regexp.MustCompile(`(?i)ghost`),
		},
		Confidence: 0.96,
	},

	// Analytics & Monitoring
	{
		Name:     "Google Analytics",
		Category: "Analytics",
		Website:  "https://analytics.google.com",
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`google-analytics\.com/(?:ga|analytics)\.js`),
			regexp.MustCompile(`googletagmanager\.com/gtag/js`),
		},
		Confidence: 0.96,
	},
	{
		Name:     "Google Tag Manager",
		Category: "Tag Manager",
		Website:  "https://tagmanager.google.com",
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`googletagmanager\.com/gtm\.js`),
		},
		Confidence: 0.96,
	},
	{
		Name:     "Sentry",
		Category: "Monitoring",
		Website:  "https://sentry.io",
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`browser\.sentry-cdn\.com`),
			regexp.MustCompile(`@sentry/browser`),
		},
		Confidence: 0.95,
	},

	// Auth Providers
	{
		Name:     "Clerk",
		Category: "Authentication Provider",
		Website:  "https://clerk.com",
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`clerk\.(?:browser|shared|accounts)\.`),
			regexp.MustCompile(`@clerk/clerk-js`),
		},
		Confidence: 0.94,
	},
	{
		Name:     "Supabase",
		Category: "Backend Platform",
		Website:  "https://supabase.com",
		ScriptURLs: []*regexp.Regexp{
			regexp.MustCompile(`@supabase/supabase-js`),
		},
		HTML: []*regexp.Regexp{
			regexp.MustCompile(`supabase\.co`),
		},
		Confidence: 0.91,
	},
}

// DetectTechnologies evaluates HTTP response headers, HTML content, and script references.
func DetectTechnologies(headers http.Header, htmlBody string, scriptURLs []string) []TechnologyFinding {
	findings := make([]TechnologyFinding, 0)
	seen := make(map[string]bool)

	metaTags := extractMetaTags(htmlBody)

	for _, sig := range techSignatures {
		evidence := make([]string, 0)

		// Check HTTP Headers
		for hName, re := range sig.Headers {
			for actualHeader, values := range headers {
				if strings.EqualFold(hName, actualHeader) {
					for _, val := range values {
						if re.MatchString(val) {
							evidence = append(evidence, fmt.Sprintf("Header %s: %s", actualHeader, val))
						}
					}
				}
			}
		}

		// Check HTML body markers
		for _, re := range sig.HTML {
			if match := re.FindString(htmlBody); match != "" {
				evidence = append(evidence, fmt.Sprintf("HTML marker match: %s", match))
			}
		}

		// Check Meta tags
		for metaName, re := range sig.Meta {
			if val, ok := metaTags[strings.ToLower(metaName)]; ok {
				if re.MatchString(val) {
					evidence = append(evidence, fmt.Sprintf("Meta %s: %s", metaName, val))
				}
			}
		}

		// Check Script URLs
		for _, scriptURL := range scriptURLs {
			for _, re := range sig.ScriptURLs {
				if re.MatchString(scriptURL) {
					evidence = append(evidence, fmt.Sprintf("Script asset URL: %s", scriptURL))
				}
			}
		}

		// Check Cookies
		for _, re := range sig.Cookies {
			for _, cookieHeader := range headers["Set-Cookie"] {
				if re.MatchString(cookieHeader) {
					evidence = append(evidence, fmt.Sprintf("Set-Cookie signature: %s", re.String()))
				}
			}
		}

		if len(evidence) > 0 && sig.Confidence >= 0.50 {
			if !seen[sig.Name] {
				seen[sig.Name] = true
				findings = append(findings, TechnologyFinding{
					Technology: sig.Name,
					Category:   sig.Category,
					Confidence: sig.Confidence,
					Evidence:   evidence,
					Website:    sig.Website,
				})
			}
		}
	}

	return findings
}

func extractMetaTags(html string) map[string]string {
	tags := make(map[string]string)
	metaRe := regexp.MustCompile(`(?i)<meta\s+[^>]*>`)
	nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	propRe := regexp.MustCompile(`(?i)property=["']([^"']+)["']`)
	contentRe := regexp.MustCompile(`(?i)content=["']([^"']+)["']`)

	for _, m := range metaRe.FindAllString(html, -1) {
		nameMatch := nameRe.FindStringSubmatch(m)
		if len(nameMatch) < 2 {
			nameMatch = propRe.FindStringSubmatch(m)
		}
		contentMatch := contentRe.FindStringSubmatch(m)
		if len(nameMatch) >= 2 && len(contentMatch) >= 2 {
			tags[strings.ToLower(nameMatch[1])] = contentMatch[1]
		}
	}

	return tags
}
