package scanner

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildRouteGraph constructs nodes and edges representing the architecture of the scanned site.
func BuildRouteGraph(targetURL string, requests []NetworkRequest, techFindings []TechnologyFinding, aiReport AIReport) RouteGraph {
	targetParsed, _ := url.Parse(targetURL)
	targetHost := ""
	if targetParsed != nil {
		targetHost = targetParsed.Host
	}

	nodesMap := make(map[string]*RouteNode)
	edges := make([]RouteEdge, 0)

	// 1. Root Browser Node
	browserNode := &RouteNode{
		ID:           "node-browser",
		Label:        "User Browser",
		Category:     "Client",
		IsThirdParty: false,
		Protocol:     "HTTPS",
		RequestCount: len(requests),
		Status:       "Active",
	}
	nodesMap["node-browser"] = browserNode

	// 2. Target Domain Node
	targetNode := &RouteNode{
		ID:           "node-target",
		Label:        targetHost,
		Category:     "Target Domain",
		IsThirdParty: false,
		Protocol:     "HTTP/2",
		RequestCount: 1,
		Status:       "Active",
	}
	nodesMap["node-target"] = targetNode

	// Connect Browser -> Target Domain
	edges = append(edges, RouteEdge{
		From:         "node-browser",
		To:           "node-target",
		Protocol:     "HTTPS",
		RequestCount: len(requests),
	})

	// 3. Cluster Requests by Host and Category
	type hostAgg struct {
		Host         string
		Category     string
		IsThirdParty bool
		Protocol     string
		RequestCount int
		LatencySum   int64
		DataSize     int64
		HasErrors    bool
	}

	hostMap := make(map[string]*hostAgg)

	for _, req := range requests {
		if req.Host == "" {
			continue
		}
		agg, ok := hostMap[req.Host]
		if !ok {
			cat := categorizeHost(req.Host, targetHost, req.Category, techFindings, aiReport)
			isTP := req.IsThirdParty || !isSameRootDomain(req.Host, targetHost)
			agg = &hostAgg{
				Host:         req.Host,
				Category:     cat,
				IsThirdParty: isTP,
				Protocol:     req.Protocol,
			}
			hostMap[req.Host] = agg
		}
		agg.RequestCount++
		agg.LatencySum += req.DurationMs
		agg.DataSize += req.EncodedSize
		if req.Status >= 400 {
			agg.HasErrors = true
		}
	}

	// Create nodes for each host cluster
	for host, agg := range hostMap {
		if host == targetHost {
			targetNode.RequestCount = agg.RequestCount
			targetNode.DataSize = agg.DataSize
			if agg.RequestCount > 0 {
				targetNode.LatencyMs = agg.LatencySum / int64(agg.RequestCount)
			}
			continue
		}

		nodeID := fmt.Sprintf("node-%s", sanitizeNodeID(host))
		status := "Healthy"
		if agg.HasErrors {
			status = "Degraded"
		}

		avgLatency := int64(0)
		if agg.RequestCount > 0 {
			avgLatency = agg.LatencySum / int64(agg.RequestCount)
		}

		proto := agg.Protocol
		if proto == "" {
			proto = "HTTPS"
		}

		node := &RouteNode{
			ID:           nodeID,
			Label:        host,
			Category:     agg.Category,
			IsThirdParty: agg.IsThirdParty,
			Protocol:     proto,
			RequestCount: agg.RequestCount,
			LatencyMs:    avgLatency,
			DataSize:     agg.DataSize,
			Status:       status,
		}
		nodesMap[nodeID] = node

		// Edge from Target Domain to Sub-resource or Service
		edges = append(edges, RouteEdge{
			From:         "node-target",
			To:           nodeID,
			Protocol:     proto,
			RequestCount: agg.RequestCount,
		})
	}

	nodesList := make([]RouteNode, 0, len(nodesMap))
	for _, n := range nodesMap {
		nodesList = append(nodesList, *n)
	}

	return RouteGraph{
		Nodes: nodesList,
		Edges: edges,
	}
}

func categorizeHost(host, targetHost, reqCat string, techFindings []TechnologyFinding, aiReport AIReport) string {
	if host == targetHost || isSameRootDomain(host, targetHost) {
		if reqCat == "xhr" || reqCat == "fetch" || strings.Contains(host, "api.") {
			return "API"
		}
		if reqCat == "script" || reqCat == "style" || strings.Contains(host, "static.") || strings.Contains(host, "assets.") {
			return "Static Assets"
		}
		return "Target Domain"
	}

	hostLower := strings.ToLower(host)

	// Check against AI Report findings
	for _, finding := range aiReport.Findings {
		if (finding.Provider != "" && strings.Contains(hostLower, strings.ToLower(finding.Provider))) ||
			(finding.Technology != "" && strings.Contains(hostLower, strings.ToLower(finding.Technology))) {
			return "AI Provider"
		}
	}

	// Check AI known hostnames
	if strings.Contains(hostLower, "openai.com") || strings.Contains(hostLower, "anthropic.com") ||
		strings.Contains(hostLower, "googleapis.com") || strings.Contains(hostLower, "pinecone.io") ||
		strings.Contains(hostLower, "weaviate") || strings.Contains(hostLower, "qdrant") {
		return "AI Provider"
	}

	// Check CDNs
	if strings.Contains(hostLower, "cloudflare") || strings.Contains(hostLower, "cloudfront") ||
		strings.Contains(hostLower, "fastly") || strings.Contains(hostLower, "akamaized") {
		return "CDN"
	}

	// Check Analytics
	if strings.Contains(hostLower, "google-analytics") || strings.Contains(hostLower, "googletagmanager") ||
		strings.Contains(hostLower, "segment") || strings.Contains(hostLower, "mixpanel") {
		return "Analytics"
	}

	// Check Auth
	if strings.Contains(hostLower, "clerk") || strings.Contains(hostLower, "auth0") ||
		strings.Contains(hostLower, "supabase.co") || strings.Contains(hostLower, "okta") {
		return "Authentication Provider"
	}

	// Check against detected technologies for CDN / Analytics / Auth
	for _, tech := range techFindings {
		techNameLower := strings.ToLower(tech.Technology)
		if techNameLower != "" && strings.Contains(hostLower, techNameLower) {
			switch tech.Category {
			case "CDN / Edge", "CDN":
				return "CDN"
			case "Analytics", "Tag Manager":
				return "Analytics"
			case "Authentication":
				return "Authentication Provider"
			}
		}
	}

	return "External Service"
}

func isSameRootDomain(hostA, hostB string) bool {
	cleanA := strings.Split(strings.ToLower(hostA), ":")[0]
	cleanB := strings.Split(strings.ToLower(hostB), ":")[0]

	partsA := strings.Split(cleanA, ".")
	partsB := strings.Split(cleanB, ".")

	if len(partsA) < 2 || len(partsB) < 2 {
		return cleanA == cleanB
	}

	rootA := partsA[len(partsA)-2] + "." + partsA[len(partsA)-1]
	rootB := partsB[len(partsB)-2] + "." + partsB[len(partsB)-1]

	return rootA == rootB
}

func sanitizeNodeID(s string) string {
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}
