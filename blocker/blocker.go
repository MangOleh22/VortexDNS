package blocker

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"vortexdns/config"
)

// BlockerState represents a point-in-time immutable snapshot of all blocking rules
type BlockerState struct {
	ExactRules     map[string]bool // Exact domain matches
	WildcardTrie   *Trie           // Wildcard matches
	WhitelistRules map[string]bool // Domain whitelist to bypass blocking
}

// Blocker is the high-performance DNS adblocker engine
type Blocker struct {
	state atomic.Pointer[BlockerState]
	cfg   *config.Config
	mu    sync.Mutex // Protects manual writes/config saves
}

// New creates a new Blocker instance
func New(cfg *config.Config) *Blocker {
	b := &Blocker{
		cfg: cfg,
	}

	// Initialize with empty state
	emptyState := &BlockerState{
		ExactRules:     make(map[string]bool),
		WildcardTrie:   NewTrie(),
		WhitelistRules: make(map[string]bool),
	}
	b.state.Store(emptyState)

	b.ReloadFromConfig()
	return b
}

// IsBlocked checks if a domain is blocked. Blazing fast, lock-free!
// Uses parent-domain walk-up to catch subdomains of blocked domains (prevents DNS leak).
func (b *Blocker) IsBlocked(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" {
		return false
	}

	// Lock-free read of current state
	state := b.state.Load()

	parts := strings.Split(domain, ".")

	// 1. Whitelist always takes priority.
	// Walk up the domain hierarchy to check if domain or any parent is whitelisted.
	// e.g., if "github.com" is whitelisted, "docs.github.com" is also allowed.
	for i := 0; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if state.WhitelistRules[parent] {
			return false
		}
	}

	// 2. Check exact blocking rules for this specific domain
	if state.ExactRules[domain] {
		return true
	}

	// 3. Parent-domain walk-up for blocking: if any PARENT domain is blocked,
	// then this subdomain is also blocked.
	// e.g., if "doubleclick.net" is blocked, "ads.doubleclick.net" is also blocked.
	// This is the fix for DNS leak via subdomain bypass.
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if state.ExactRules[parent] {
			return true
		}
	}

	// 4. Check wildcard blocking rules using our Trie
	if state.WildcardTrie.Match(domain) {
		return true
	}

	return false
}

// ReloadFromConfig rebuilds the blocking state using current configuration
func (b *Blocker) ReloadFromConfig() {
	b.mu.Lock()
	defer b.mu.Unlock()

	newState := &BlockerState{
		ExactRules:     make(map[string]bool),
		WildcardTrie:   NewTrie(),
		WhitelistRules: make(map[string]bool),
	}

	// Load custom whitelist
	for _, entry := range b.cfg.CustomWhitelist {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry != "" {
			newState.WhitelistRules[entry] = true
		}
	}

	// Load custom blacklist
	for _, entry := range b.cfg.CustomBlacklist {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			newState.WildcardTrie.Insert(entry)
		} else {
			newState.ExactRules[entry] = true
		}
	}

	// Atomically swap the state
	b.state.Store(newState)
}

// SwapState replaces the blocker rules with new compiled ones from updaters.
// This is called by the background blocklist updater.
func (b *Blocker) SwapState(exact map[string]bool, wildcards []string, remoteWhitelist map[string]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	newState := &BlockerState{
		ExactRules:     make(map[string]bool),
		WildcardTrie:   NewTrie(),
		WhitelistRules: make(map[string]bool),
	}

	// Re-add whitelists
	for _, entry := range b.cfg.CustomWhitelist {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry != "" {
			newState.WhitelistRules[entry] = true
		}
	}
	
	// Add remote whitelists
	for entry := range remoteWhitelist {
		newState.WhitelistRules[entry] = true
	}

	// Re-add custom blacklists
	for _, entry := range b.cfg.CustomBlacklist {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "*.") {
			newState.WildcardTrie.Insert(entry)
		} else {
			newState.ExactRules[entry] = true
		}
	}

	// Add remote blocklist rules (exact matches)
	for d := range exact {
		// Ignore if it's on custom whitelist
		if newState.WhitelistRules[d] {
			continue
		}
		newState.ExactRules[d] = true
	}

	// Add remote blocklist rules (wildcard matches)
	for _, w := range wildcards {
		cleanW := strings.TrimPrefix(w, "*.")
		if newState.WhitelistRules[cleanW] {
			continue
		}
		newState.WildcardTrie.Insert(w)
	}

	// Atomically swap
	b.state.Store(newState)
}

// GetStats returns current rule counts
func (b *Blocker) GetStats() (exact int, wildcards int, whitelist int) {
	state := b.state.Load()
	return len(state.ExactRules), 0, len(state.WhitelistRules) // Wildcard trie size is tricky, but exact is key
}

// AddWhitelist adds a domain to custom whitelist
func (b *Blocker) AddWhitelist(domain string) {
        domain = strings.TrimSpace(strings.ToLower(domain))
        if domain == "" {
                return
        }

        b.mu.Lock()
        f, err := os.OpenFile(filepath.Join(b.cfg.DatabaseDir, "custom_web_whitelist.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
                f.WriteString(domain + "\n")
                f.Close()
        }
        b.mu.Unlock()

        b.cfg.CustomWhitelist = append(b.cfg.CustomWhitelist, domain)
        b.ReloadFromConfig()
}

// RemoveWhitelist removes a domain from custom whitelist
func (b *Blocker) RemoveWhitelist(domain string) {
        domain = strings.TrimSpace(strings.ToLower(domain))
        
        b.mu.Lock()
        var newL []string
        for _, entry := range b.cfg.CustomWhitelist {
                if entry != domain {
                        newL = append(newL, entry)
                }
        }
        b.cfg.CustomWhitelist = newL

        filePath := filepath.Join(b.cfg.DatabaseDir, "custom_web_whitelist.txt")
        data, err := os.ReadFile(filePath)
        if err == nil {
                lines := strings.Split(string(data), "\n")
                var newLines []string
                for _, l := range lines {
                        if strings.TrimSpace(l) != domain && l != "" {
                                newLines = append(newLines, l)
                        }
                }
                os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
        }
        b.mu.Unlock()

        b.ReloadFromConfig()
}

// AddBlacklist adds a domain to custom blacklist
func (b *Blocker) AddBlacklist(domain string) {
        domain = strings.TrimSpace(strings.ToLower(domain))
        if domain == "" {
                return
        }

        b.mu.Lock()
        // Save directly to lists folder
        f, err := os.OpenFile(filepath.Join(b.cfg.DatabaseDir, "lists", "custom_web_blacklist.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err == nil {
                f.WriteString(domain + "\n")
                f.Close()
        }
        b.mu.Unlock()

        // Also add to current config in-memory for instant effect if not there
        b.cfg.CustomBlacklist = append(b.cfg.CustomBlacklist, domain)
        b.ReloadFromConfig()
}

// RemoveBlacklist removes a domain from custom blacklist
func (b *Blocker) RemoveBlacklist(domain string) {
        domain = strings.TrimSpace(strings.ToLower(domain))
        
        b.mu.Lock()
        // Remove from memory
        var newL []string
        for _, entry := range b.cfg.CustomBlacklist {
                if entry != domain {
                        newL = append(newL, entry)
                }
        }
        b.cfg.CustomBlacklist = newL

        // Re-write custom file
        filePath := filepath.Join(b.cfg.DatabaseDir, "lists", "custom_web_blacklist.txt")
        data, err := os.ReadFile(filePath)
        if err == nil {
                lines := strings.Split(string(data), "\n")
                var newLines []string
                for _, l := range lines {
                        if strings.TrimSpace(l) != domain && l != "" {
                                newLines = append(newLines, l)
                        }
                }
                os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
        }
        b.mu.Unlock()

        b.ReloadFromConfig()
}

// GetRules returns the list of current custom rules
func (b *Blocker) GetRules() (blacklist []string, whitelist []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.CustomBlacklist, b.cfg.CustomWhitelist
}
