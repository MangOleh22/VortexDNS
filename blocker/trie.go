package blocker

import (
	"strings"
)

// TrieNode represents a single node in the Domain Trie
type TrieNode struct {
	Children   map[string]*TrieNode
	IsBlocked  bool // If true, matches this exact domain and any subdomains
}

// NewTrieNode creates a new TrieNode
func NewTrieNode() *TrieNode {
	return &TrieNode{
		Children: make(map[string]*TrieNode),
	}
}

// Trie represents a high-performance domain matching Trie
type Trie struct {
	Root *TrieNode
}

// NewTrie creates a new Trie
func NewTrie() *Trie {
	return &Trie{
		Root: NewTrieNode(),
	}
}

// Insert inserts a domain rule into the Trie.
// If the domain starts with "*.", it is treated as a wildcard rule.
// We reverse the domain labels so we can match suffix wildcards efficiently.
func (t *Trie) Insert(domain string) {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" {
		return
	}

	isWildcard := false
	if strings.HasPrefix(domain, "*.") {
		isWildcard = true
		domain = domain[2:]
	}

	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return
	}

	current := t.Root
	// Walk in reverse order (e.g. "ads.doubleclick.net" -> "net", "doubleclick", "ads")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		child, exists := current.Children[part]
		if !exists {
			child = NewTrieNode()
			current.Children[part] = child
		}
		current = child
	}

	// Mark the endpoint
	current.IsBlocked = true
	// If it is a wildcard rule, it covers all subdomains automatically,
	// but standard exact blocking in a trie can also act as wildcard blocker depending on match logic.
	// In our design, if any parent node along the match path is marked as blocked,
	// it's a match. If isWildcard is true, we block all subdomains.
	// Actually, if we block "doubleclick.net", we usually block "ads.doubleclick.net" too.
	// So both wildcard and exact suffixes can be walked in reverse.
	_ = isWildcard // We can treat it uniformly: if a parent domain is blocked, then all subdomains are blocked.
}

// Match checks if a domain matches any blocking rule in the Trie.
// It reverses the query labels and walks down the tree. If it hits a node with IsBlocked == true,
// it means this domain is a subdomain of a blocked domain (or is the blocked domain itself).
func (t *Trie) Match(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" {
		return false
	}

	parts := strings.Split(domain, ".")
	current := t.Root

	// Walk in reverse order (e.g., net -> doubleclick -> ads)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		child, exists := current.Children[part]
		if !exists {
			break
		}
		
		current = child
		if current.IsBlocked {
			// Found a blocking rule! For example, if we blocked "doubleclick.net"
			// and we are querying "ads.doubleclick.net", when we reach "doubleclick",
			// IsBlocked is true, so we match (block it).
			return true
		}
	}

	return false
}
