package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// AISignature defines a rule for identifying AI frameworks, providers, or interfaces.
type AISignature struct {
	Provider   string
	Technology string
	Capability string
	Category   string // "AI SDK", "Model Provider", "Vector DB", "AI Tooling", "Protocol"
	Pattern    *regexp.Regexp
	Confidence float64
	Exposure   string
	Risk       string
}

// Built-in AI detection signatures
var aiSignatures = []AISignature{
	// SDKs & Frameworks
	{
		Provider:   "Vercel",
		Technology: "Vercel AI SDK",
		Capability: "Client-side LLM streaming & UI hooks",
		Category:   "AI SDK",
		Pattern:    regexp.MustCompile(`(?i)(?:useChat|useCompletion|ai/react|@ai-sdk/react|ai/streams)`),
		Confidence: 0.95,
		Exposure:   "Frontend JavaScript Bundle",
		Risk:       "Verify inference requests route through server-side authenticated endpoints.",
	},
	{
		Provider:   "LangChain",
		Technology: "LangChain",
		Capability: "Chains, Agents, and LLM orchestration",
		Category:   "AI SDK",
		Pattern:    regexp.MustCompile(`(?i)(?:@langchain/|langchain/core|langchain/schema)`),
		Confidence: 0.94,
		Exposure:   "Frontend JavaScript Bundle",
		Risk:       "Ensure prompts, chains, and internal agent tools are not exposed directly in client code.",
	},
	{
		Provider:   "LlamaIndex",
		Technology: "LlamaIndex",
		Capability: "RAG index & data connectors",
		Category:   "AI SDK",
		Pattern:    regexp.MustCompile(`(?i)(?:llamaindex|@llamaindex/core)`),
		Confidence: 0.92,
		Exposure:   "Frontend Bundle",
		Risk:       "Ensure document indexes and vector storage credentials remain server-side.",
	},

	// Providers
	{
		Provider:   "OpenAI",
		Technology: "OpenAI API",
		Capability: "GPT model inference & embeddings",
		Category:   "Model Provider",
		Pattern:    regexp.MustCompile(`(?i)(?:api\.openai\.com|openai-organization|gpt-4o|gpt-4|gpt-3\.5-turbo)`),
		Confidence: 0.96,
		Exposure:   "Public Network Request / Bundle",
		Risk:       "Exposing direct OpenAI endpoint references in client code may risk token or prompt leaks.",
	},
	{
		Provider:   "Anthropic",
		Technology: "Anthropic Claude API",
		Capability: "Claude model inference",
		Category:   "Model Provider",
		Pattern:    regexp.MustCompile(`(?i)(?:api\.anthropic\.com|claude-3|claude-3-5|claude-2)`),
		Confidence: 0.96,
		Exposure:   "Public Network Request / Bundle",
		Risk:       "Ensure direct API calls to api.anthropic.com are proxied via a backend gateway.",
	},
	{
		Provider:   "Google",
		Technology: "Google Gemini API",
		Capability: "Gemini multimodal inference",
		Category:   "Model Provider",
		Pattern:    regexp.MustCompile(`(?i)(?:generativelanguage\.googleapis\.com|gemini-1\.5-pro|gemini-1\.5-flash|@google/generative-ai)`),
		Confidence: 0.95,
		Exposure:   "Public Network Request / Bundle",
		Risk:       "Ensure Gemini API keys are restricted or stored exclusively in server environment.",
	},
	{
		Provider:   "Hugging Face",
		Technology: "Hugging Face Inference",
		Capability: "Open-weights model serving",
		Category:   "Model Provider",
		Pattern:    regexp.MustCompile(`(?i)(?:api-inference\.huggingface\.co|@huggingface/inference)`),
		Confidence: 0.93,
		Exposure:   "Client Bundle / API",
		Risk:       "Protect API tokens and rate limits against abuse.",
	},
	{
		Provider:   "Ollama",
		Technology: "Ollama Local AI",
		Capability: "Local model inference server",
		Category:   "Model Provider",
		Pattern:    regexp.MustCompile(`(?i)(?:localhost:11434|127\.0\.0\.1:11434|ollama/api)`),
		Confidence: 0.90,
		Exposure:   "Client Scripts",
		Risk:       "Local daemon endpoint exposed in public bundle.",
	},

	// Vector Databases
	{
		Provider:   "Pinecone",
		Technology: "Pinecone Vector DB",
		Capability: "Vector search & indexing",
		Category:   "Vector DB",
		Pattern:    regexp.MustCompile(`(?i)(?:svc\.pinecone\.io|@pinecone-database/pinecone)`),
		Confidence: 0.95,
		Exposure:   "Client Bundle / Network",
		Risk:       "Vector database credentials must never reside on client devices.",
	},
	{
		Provider:   "Weaviate",
		Technology: "Weaviate",
		Capability: "Vector search engine",
		Category:   "Vector DB",
		Pattern:    regexp.MustCompile(`(?i)(?:weaviate-client|weaviate\.network)`),
		Confidence: 0.93,
		Exposure:   "Client Bundle",
		Risk:       "Vector index query endpoints must be protected behind auth gates.",
	},
	{
		Provider:   "Qdrant",
		Technology: "Qdrant",
		Capability: "Vector similarity search",
		Category:   "Vector DB",
		Pattern:    regexp.MustCompile(`(?i)(?:@qdrant/js-client-rest|qdrant\.tech)`),
		Confidence: 0.92,
		Exposure:   "Client Bundle",
		Risk:       "Prevent unfiltered vector space queries.",
	},

	// Standards & Protocols
	{
		Provider:   "Standard",
		Technology: "llms.txt Standard",
		Capability: "Structured documentation for LLM ingestion",
		Category:   "Protocol",
		Pattern:    regexp.MustCompile(`(?i)/llms\.txt`),
		Confidence: 0.98,
		Exposure:   "Root domain endpoint",
		Risk:       "Public standard file for LLM documentation; keep synchronized.",
	},
}

// SecretPattern defines an API credential pattern that must be detected and REDACTED.
type SecretPattern struct {
	Type     string
	Pattern  *regexp.Regexp
	Severity Severity
}

var secretPatterns = []SecretPattern{
	{
		Type:     "OpenAI API Key",
		Pattern:  regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b`),
		Severity: SeverityCritical,
	},
	{
		Type:     "Google AI / Gemini API Key",
		Pattern:  regexp.MustCompile(`\b(AIzaSy[A-Za-z0-9_-]{33})\b`),
		Severity: SeverityCritical,
	},
	{
		Type:     "Anthropic API Key",
		Pattern:  regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_-]{20,})\b`),
		Severity: SeverityCritical,
	},
	{
		Type:     "Hugging Face User Access Token",
		Pattern:  regexp.MustCompile(`\b(hf_[A-Za-z0-9]{34})\b`),
		Severity: SeverityHigh,
	},
}

// RedactSecret masks discovered credentials preserving only prefix and suffix.
// Example: "sk-proj-1234567890abcdef91Ax" -> "sk-proj-****************91Ax"
func RedactSecret(secret string) string {
	if len(secret) <= 10 {
		return "********"
	}
	prefixLen := 7
	if strings.HasPrefix(secret, "sk-proj-") {
		prefixLen = 8
	} else if strings.HasPrefix(secret, "sk-ant-") {
		prefixLen = 7
	} else if strings.HasPrefix(secret, "AIzaSy") {
		prefixLen = 6
	} else if strings.HasPrefix(secret, "hf_") {
		prefixLen = 3
	}

	if prefixLen >= len(secret)-4 {
		prefixLen = 3
	}

	suffixLen := 4
	maskedLen := len(secret) - prefixLen - suffixLen
	if maskedLen < 4 {
		maskedLen = 4
	}

	return secret[:prefixLen] + strings.Repeat("*", maskedLen) + secret[len(secret)-suffixLen:]
}

// DetectAI analyzes public assets, scripts, endpoints, and HTML for AI-native capabilities and secrets.
func DetectAI(htmlBody string, scriptBodies map[string]string, endpoints []string, hasLLMSTxt bool) AIReport {
	findings := make([]AIFinding, 0)
	secrets := make([]SecretFinding, 0)
	securityFindings := make([]SecurityFinding, 0)
	seen := make(map[string]bool)

	// 1. Scan for llms.txt standard
	if hasLLMSTxt {
		findings = append(findings, AIFinding{
			Provider:   "Standard",
			Technology: "llms.txt Specification",
			Capability: "Curated site context formatted for AI assistants and LLMs",
			Confidence: 0.99,
			Evidence:   []string{"Found publicly served /llms.txt at root domain"},
			Exposure:   "Public Root Document",
			Risk:       "Informational standard; verify documentation accuracy.",
		})
	}

	// 2. Scan HTML body
	for _, sig := range aiSignatures {
		if sig.Pattern.MatchString(htmlBody) {
			key := sig.Provider + ":" + sig.Technology
			if !seen[key] {
				seen[key] = true
				findings = append(findings, AIFinding{
					Provider:   sig.Provider,
					Technology: sig.Technology,
					Capability: sig.Capability,
					Confidence: sig.Confidence,
					Evidence:   []string{fmt.Sprintf("Signature match in main page HTML: %s", sig.Pattern.String())},
					Exposure:   sig.Exposure,
					Risk:       sig.Risk,
				})
			}
		}
	}

	// 3. Scan Public JavaScript Bundles & Endpoints
	for scriptURL, body := range scriptBodies {
		// Detect AI Frameworks / SDKs
		for _, sig := range aiSignatures {
			if sig.Pattern.MatchString(body) {
				key := sig.Provider + ":" + sig.Technology
				if !seen[key] {
					seen[key] = true
					findings = append(findings, AIFinding{
						Provider:   sig.Provider,
						Technology: sig.Technology,
						Capability: sig.Capability,
						Confidence: sig.Confidence,
						Evidence:   []string{fmt.Sprintf("Signature discovered in script asset: %s", scriptURL)},
						Exposure:   sig.Exposure,
						Risk:       sig.Risk,
					})
				}
			}
		}

		// Detect Exposed Secrets (WITH IMMEDIATE REDACTION)
		for _, sp := range secretPatterns {
			matches := sp.Pattern.FindAllString(body, -1)
			for _, match := range matches {
				redacted := RedactSecret(match)
				secrets = append(secrets, SecretFinding{
					SecretType:    sp.Type,
					Location:      fmt.Sprintf("Client script asset: %s", scriptURL),
					RedactedValue: redacted,
					Severity:      sp.Severity,
					Confidence:    0.95,
				})

				// Create actionable SecurityFinding
				secID := fmt.Sprintf("AI-SEC-%03d", len(securityFindings)+1)
				securityFindings = append(securityFindings, SecurityFinding{
					ID:         secID,
					Category:   "ai_security",
					Severity:   sp.Severity,
					Confidence: 0.95,
					Title:      fmt.Sprintf("Exposed %s in public client bundle", sp.Type),
					Description: fmt.Sprintf("An API credential (%s) was observed inside a client-accessible JavaScript file. Public exposure enables unauthorized consumption of model quotas, potential data exfiltration, or financial abuse.", sp.Type),
					Evidence: map[string]interface{}{
						"secret_type": sp.Type,
						"asset":       scriptURL,
						"redacted":    redacted,
					},
					Impact:         "Unauthorized access to model APIs, quota exhaustion, financial billing spikes.",
					Likelihood:     "High",
					AffectedAsset:  scriptURL,
					Effort:         "Small",
					Priority:       "P0",
					MitigationTime: "Immediate",
					Mitigation: RemediationDetail{
						Action:                 "Rotate the exposed API credential immediately and move all model requests behind a server-side API gateway.",
						TechnicalFix:           "1. Revoke the key in the provider console.\n2. Store new key in server environment variables (e.g. process.env.OPENAI_API_KEY).\n3. Implement a backend proxy route (e.g. /api/chat) that enforces session authentication.",
						ExpectedResult:         "Client bundles no longer contain raw provider keys.",
						Verification:           "Re-scan the website and verify that no credentials match in downloaded bundles.",
						ImplementationExample: "// Bad:\nconst client = new OpenAI({ apiKey: 'sk-...' });\n\n// Good:\nconst response = await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ prompt }) });",
					},
				})
			}
		}
	}

	// 4. Scan Discovered Endpoint URLs for public streaming/chat routes
	endpointRe := regexp.MustCompile(`(?i)(?:/api/chat|/api/generate|/api/completion|/v1/chat/completions)`)
	for _, ep := range endpoints {
		if endpointRe.MatchString(ep) {
			findings = append(findings, AIFinding{
				Provider:   "Public Inference Route",
				Technology: "HTTP Streaming Inference Endpoint",
				Capability: "Exposed API route for chat or text completion",
				Confidence: 0.91,
				Evidence:   []string{fmt.Sprintf("Discovered public route: %s", ep)},
				Exposure:   "Public API Route",
				Risk:       "Verify that this route enforces rate limiting, CSRF tokens, and authentication.",
			})

			secID := fmt.Sprintf("AI-SEC-%03d", len(securityFindings)+1)
			securityFindings = append(securityFindings, SecurityFinding{
				ID:         secID,
				Category:   "ai_security",
				Severity:   SeverityMedium,
				Confidence: 0.88,
				Title:      "Public AI inference endpoint detected",
				Description: fmt.Sprintf("The website exposes an inference route (%s). If unauthenticated, it may be subject to bot scraping or Denial of Wallet attacks.", ep),
				Evidence: map[string]interface{}{
					"route": ep,
				},
				Impact:         "Unrestricted model invocation may cause excessive billing or resource degradation.",
				Likelihood:     "Medium",
				AffectedAsset:  ep,
				Effort:         "Medium",
				Priority:       "P1",
				MitigationTime: "Short-term",
				Mitigation: RemediationDetail{
					Action:         "Implement rate limiting (e.g. token bucket per IP/user) and session authentication on inference routes.",
					TechnicalFix:   "Add middleware to validate bearer JWT or session cookie and enforce strict QPS caps.",
					ExpectedResult: "Anonymous automated requests receive HTTP 429 Too Many Requests.",
					Verification:   "Send 5 consecutive curl requests to the route without cookies; verify rate limit activation.",
				},
			})
		}
	}

	// 5. Determine Overall Classification
	classification := "No public AI evidence detected"
	overallConfidence := 0.0

	if len(findings) > 0 {
		var totalConf float64
		for _, f := range findings {
			totalConf += f.Confidence
		}
		overallConfidence = totalConf / float64(len(findings))

		hasSDK := false
		hasProvider := false
		for _, f := range findings {
			if strings.Contains(f.Technology, "Vercel AI") || strings.Contains(f.Technology, "LangChain") || strings.Contains(f.Technology, "LlamaIndex") {
				hasSDK = true
			}
			if strings.Contains(f.Provider, "OpenAI") || strings.Contains(f.Provider, "Anthropic") || strings.Contains(f.Provider, "Google") {
				hasProvider = true
			}
		}

		if hasSDK && hasProvider {
			classification = "AI-native architecture indicators"
		} else if hasSDK || hasProvider {
			classification = "AI-enabled"
		} else {
			classification = "AI-assisted"
		}
	}

	observability := map[string]string{
		"model_request_tracing": "Unable to verify externally",
		"token_usage_visibility": "Unable to verify externally",
		"provider_latency":       "Unable to verify externally",
		"stream_cancellation":    "Unable to verify externally",
		"cost_observability":     "Unable to verify externally",
	}

	return AIReport{
		Classification:   classification,
		Confidence:       overallConfidence,
		Findings:         findings,
		SecurityFindings: securityFindings,
		Secrets:          secrets,
		Observability:    observability,
	}
}
