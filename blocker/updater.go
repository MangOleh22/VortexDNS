package blocker

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vortexdns/config"
)

// BlockerUpdater handles remote ad-blocklist downloading and caching
type BlockerUpdater struct {
	blocker       *Blocker
	cfg           *config.Config
	mu            sync.Mutex
	IsUpdating    bool
	LastUpdate    time.Time
	TotalRules    int
	DownloadedLen int
	UpdateError   string
}

// NewUpdater creates a new BlockerUpdater
func NewUpdater(b *Blocker, cfg *config.Config) *BlockerUpdater {
	u := &BlockerUpdater{
		blocker: b,
		cfg:     cfg,
	}

	// Try to load cached local lists on startup for immediate operation
	go u.LoadCachedLists()

	return u
}

// LoadCachedLists loads previously downloaded files from disk synchronously/asynchronously on start
func (u *BlockerUpdater) LoadCachedLists() {
	u.mu.Lock()
	if u.IsUpdating {
		u.mu.Unlock()
		return
	}
	u.IsUpdating = true
	u.mu.Unlock()

	defer func() {
		u.mu.Lock()
		u.IsUpdating = false
		u.mu.Unlock()
	}()

	exact := make(map[string]bool)
	wildcards := []string{}

	dir := filepath.Join(u.cfg.DatabaseDir, "lists")
	_ = os.MkdirAll(dir, 0755)

	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	loadedAny := false
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(dir, file.Name())
		f, err := os.Open(filePath)
		if err != nil {
			continue
		}

		u.parseHostsReader(f, exact, &wildcards)
		f.Close()
		loadedAny = true
	}

	if loadedAny {
		u.blocker.SwapState(exact, wildcards, make(map[string]bool))
		u.mu.Lock()
		u.TotalRules = len(exact) + len(wildcards)
		u.LastUpdate = time.Now()
		u.mu.Unlock()
		log.Printf("[Blocker] Loaded %d cached adblocking rules from disk", u.TotalRules)
	}
}

// StartUpdate triggers the asynchronous background update of all configured blocklists
func (u *BlockerUpdater) StartUpdate() {
	u.mu.Lock()
	if u.IsUpdating {
		u.mu.Unlock()
		return
	}
	u.IsUpdating = true
	u.UpdateError = ""
	u.mu.Unlock()

	go func() {
		defer func() {
			u.mu.Lock()
			u.IsUpdating = false
			u.mu.Unlock()
		}()

		exact := make(map[string]bool)
		wildcards := []string{}

		listDir := filepath.Join(u.cfg.DatabaseDir, "lists")
		_ = os.MkdirAll(listDir, 0755)

		var wg sync.WaitGroup
		var mapMu sync.Mutex

		httpClient := &http.Client{
			Timeout: 45 * time.Second,
		}

		for _, urlStr := range u.cfg.BlocklistURLs {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" {
				continue
			}

			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				
				var reader io.Reader

				isLocal := isLocalPath(url)
				if isLocal {
					localPath, err := u.safeLocalPath(url)
					if err != nil {
						log.Printf("[Updater] Keamanan: path blocklist ditolak %q: %v", url, err)
						u.mu.Lock()
						u.UpdateError = fmt.Sprintf("Path tidak diizinkan: %v", err)
						u.mu.Unlock()
						return
					}
					log.Printf("[Updater] Reading local blocklist: %s", localPath)
					file, err := os.Open(localPath)
					if err != nil {
						log.Printf("[Updater] Failed to open local blocklist %s: %v", localPath, err)
						u.mu.Lock()
						u.UpdateError = fmt.Sprintf("File open failed for %s", localPath)
						u.mu.Unlock()
						return
					}
					defer file.Close()
					
					// Cache to vortex_db/lists for quick startup loading
					hasher := md5.New()
					hasher.Write([]byte(url))
					hashName := hex.EncodeToString(hasher.Sum(nil)) + ".txt"
					cachePath := filepath.Join(listDir, hashName)
					
					tempFile, err := os.Create(cachePath)
					if err == nil {
						defer tempFile.Close()
						reader = io.TeeReader(file, tempFile)
					} else {
						reader = file
					}
				} else {
					log.Printf("[Updater] Downloading: %s", url)
					resp, err := httpClient.Get(url)
					if err != nil {
						log.Printf("[Updater] Download failed for %s: %v", url, err)
						u.mu.Lock()
						u.UpdateError = fmt.Sprintf("Download failed for %s", url)
						u.mu.Unlock()
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						log.Printf("[Updater] Bad status code %d for %s", resp.StatusCode, url)
						return
					}
					
					// Cache to file using a hash of the URL
					hasher := md5.New()
					hasher.Write([]byte(url))
					hashName := hex.EncodeToString(hasher.Sum(nil)) + ".txt"
					cachePath := filepath.Join(listDir, hashName)

					tempFile, err := os.Create(cachePath)
					if err != nil {
						log.Printf("[Updater] Failed to create cache file: %v", err)
						return
					}
					defer tempFile.Close()

					// Read, save to temp file, and parse at the same time
					reader = io.TeeReader(resp.Body, tempFile)
				}

				localExact := make(map[string]bool)
				localWildcards := []string{}

				u.parseHostsReader(reader, localExact, &localWildcards)

				mapMu.Lock()
				for k := range localExact {
					exact[k] = true
				}
				wildcards = append(wildcards, localWildcards...)
				mapMu.Unlock()

				log.Printf("[Updater] Finished processing %s: found %d rules", url, len(localExact)+len(localWildcards))
			}(urlStr)
		}

		// Also download whitelist URLs
		remoteWhitelist := make(map[string]bool)
		for _, urlStr := range u.cfg.WhitelistURLs {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr == "" {
				continue
			}

			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				
				var reader io.Reader
				
				isLocal := isLocalPath(url)
				if isLocal {
					localPath, err := u.safeLocalPath(url)
					if err != nil {
						log.Printf("[Updater] Keamanan: path whitelist ditolak %q: %v", url, err)
						return
					}
					log.Printf("[Updater] Reading local whitelist: %s", localPath)
					file, err := os.Open(localPath)
					if err != nil {
						log.Printf("[Updater] Failed to open local whitelist %s: %v", localPath, err)
						return
					}
					defer file.Close()
					
					// Cache to vortex_db/lists for quick startup loading
					hasher := md5.New()
					hasher.Write([]byte(url))
					hashName := hex.EncodeToString(hasher.Sum(nil)) + ".txt"
					cachePath := filepath.Join(listDir, hashName)
					
					tempFile, err := os.Create(cachePath)
					if err == nil {
						defer tempFile.Close()
						reader = io.TeeReader(file, tempFile)
					} else {
						reader = file
					}
				} else {
					log.Printf("[Updater] Downloading whitelist: %s", url)
					resp, err := httpClient.Get(url)
					if err != nil {
						log.Printf("[Updater] Whitelist download failed for %s: %v", url, err)
						return
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return
					}
					reader = resp.Body
				}

				localExact := make(map[string]bool)
				localWildcards := []string{}
				u.parseHostsReader(reader, localExact, &localWildcards)

				mapMu.Lock()
				for k := range localExact {
					remoteWhitelist[k] = true
				}
				mapMu.Unlock()
				log.Printf("[Updater] Finished processing whitelist %s", url)
			}(urlStr)
		}

		wg.Wait()

		// Apply the new state
		u.blocker.SwapState(exact, wildcards, remoteWhitelist)

		u.mu.Lock()
		u.TotalRules = len(exact) + len(wildcards)
		u.LastUpdate = time.Now()
		u.mu.Unlock()

		log.Printf("[Updater] Blocklist update finished. Total loaded rules: %d", u.TotalRules)
	}()
}

// safeLocalPath memvalidasi bahwa berkas lokal harus berada di dalam DatabaseDir,
// mencegah eksploitasi Local File Inclusion (LFI) dan pembacaan berkas sistem sembarang.
func (u *BlockerUpdater) safeLocalPath(src string) (string, error) {
	cleanSrc := strings.TrimPrefix(src, "file://")
	cleaned := filepath.Clean(cleanSrc)
	if !filepath.IsAbs(cleaned) {
		cleaned = filepath.Clean(filepath.Join(u.cfg.DatabaseDir, cleaned))
	}
	dbDirAbs, err := filepath.Abs(u.cfg.DatabaseDir)
	if err != nil {
		return "", fmt.Errorf("invalid database dir")
	}
	targetAbs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid file path")
	}
	rel, err := filepath.Rel(dbDirAbs, targetAbs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("akses ditolak: path harus berada di dalam direktori %s", u.cfg.DatabaseDir)
	}
	return targetAbs, nil
}

// isLocalPath reports whether a blocklist/whitelist source is a local file
// rather than a remote URL. Anything that is not an http(s) URL is treated as a
// local path: explicit file:// scheme, absolute paths, or repo-relative paths
// like "vortex_db/lists/foo.txt". This keeps bundled offline lists working.
func isLocalPath(src string) bool {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return false
	}
	return true
}

// parseHostsReader reads hosts file data from reader and extracts domains
func (u *BlockerUpdater) parseHostsReader(r io.Reader, exact map[string]bool, wildcards *[]string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Ignore empty lines and comments (hosts '#' or AdBlock '!')
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Handle AdBlock syntax
		isAdBlock := false
		if strings.HasPrefix(line, "@@||") {
			line = strings.TrimPrefix(line, "@@||")
			isAdBlock = true
		} else if strings.HasPrefix(line, "||") {
			line = strings.TrimPrefix(line, "||")
			isAdBlock = true
		}

		if isAdBlock {
			// Strip everything from the first special char: ^, /, :, *, |
			for _, char := range []string{"^", "/", ":", "*", "|"} {
				if idx := strings.Index(line, char); idx != -1 {
					line = line[:idx]
				}
			}
		}

		// Split on whitespace
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Handle hosts file format: "0.0.0.0 adserver.com" or just "adserver.com"
		var domain string
		if len(fields) == 1 {
			domain = fields[0]
		} else {
			// Often "127.0.0.1 domain.com" or "0.0.0.0 domain.com"
			// Verify if the first field looks like an IP
			if fields[0] == "127.0.0.1" || fields[0] == "0.0.0.0" || strings.Contains(fields[0], ".") || strings.Contains(fields[0], ":") {
				domain = fields[1]
			} else {
				domain = fields[0]
			}
		}

		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" || domain == "localhost" || domain == "localhost.localdomain" {
			continue
		}

		if strings.HasPrefix(domain, "*.") {
			*wildcards = append(*wildcards, domain)
		} else {
			exact[domain] = true
		}
	}
}

// GetStatus returns the current downloader/updater status info
func (u *BlockerUpdater) GetStatus() (isUpdating bool, totalRules int, lastUpdate time.Time, errStr string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.IsUpdating, u.TotalRules, u.LastUpdate, u.UpdateError
}
