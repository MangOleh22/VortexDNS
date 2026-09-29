package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"vortexdns/blocker"
	"vortexdns/cache"
	"vortexdns/config"
	"vortexdns/dashboard"
	"vortexdns/dns"
	"vortexdns/forwarder"
	"vortexdns/storage"
)

func main() {
	// Parse CLI flags
	configPath := flag.String("config", "config.json", "Path to config file")
	installFlag := flag.Bool("install", false, "Install VortexDNS as a systemd service")
	resetPassword := flag.Bool("reset-password", false, "Reset the admin password, then exit (works inside any container)")
	resetUsername := flag.String("reset-username", "", "Set the admin username alongside -reset-password")
	flag.Parse()

	if *installFlag {
		installService(*configPath)
		return
	}

	if *resetPassword {
		if err := resetAdminCredentials(*configPath, *resetUsername); err != nil {
			log.Fatalf("[Reset] %v", err)
		}
		return
	}

	log.Println(`
   _  __           __            ___  _  ______
  | |/ /__  ______/ /____ __ __ / _ \/ |/ / __/
  |  // _ \/ __/ __/ __/\ \ // // // /    /\ \  
  |_/ \___/_/  \__/\__/ /_\_\\_,_//___/_/|_/___/  v1.0.0
  High-Performance Zero-Lock DNS Adblocker Server
	`)

	// 1. Load or generate configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[Main] Critical error loading config: %v", err)
	}
	// Route process output to a file when configured. Left empty when running
	// from a terminal, so vortex.log only appears once installed.
	if closeLog := setupProcessLog(cfg.LogFilePath); closeLog != nil {
		defer closeLog()
	}

	log.Printf("[Main] Config loaded successfully from %s", *configPath)
	log.Printf("[Main] Configured Upstreams: %v", cfg.UpstreamServers)

	// 1.5. Open SQLite storage
	log.Println("[Main] Opening SQLite storage...")
	store, err := storage.Open(cfg.DatabaseDir)
	if err != nil {
		log.Fatalf("[Main] Failed to open storage: %v", err)
	}
	defer store.Close()

	// 2. Initialize Core components
	log.Println("[Main] Initializing high-performance lock-free Blocker...")
	adBlocker := blocker.New(cfg)

	log.Println("[Main] Initializing non-blocking Blocker Updater...")
	adUpdater := blocker.NewUpdater(adBlocker, cfg)

	log.Println("[Main] Initializing 64-sharded DNS Cache (Prefetching Enabled)...")
	dnsCache := cache.New(cfg.CacheSize, cfg.CacheMinTTL, cfg.CacheMaxTTL, cfg.CachePrefetch)

	log.Println("[Main] Initializing RTT-Aware Smart Upstream Forwarder...")
	dnsForwarder := forwarder.New(cfg.UpstreamServers, cfg.FailoverUpstreams)

	// 3. Initialize DNS Server & Dashboard
	log.Println("[Main] Assembling DNS query processing pipeline...")
	dnsServer := dns.NewServer(cfg, adBlocker, dnsCache, dnsForwarder)

	log.Println("[Main] Preparing Glassmorphic Dashboard and REST endpoints...")
	dashboardServer := dashboard.New(cfg, dnsServer, adBlocker, adUpdater, dnsCache, dnsForwarder, store)

	// 4. Start servers
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("[Main] DNS server startup failed: %v", err)
	}

	// 4.5 Setup Transparent Proxy for VPN routing
	dnsServer.Advanced().SetupTransparentProxy(cfg.BindAddress)

	dashboardServer.Start()

	// 5. Smart Bootstrapping: If database has 0 rules, trigger a sync in the background automatically
	go func() {
		// Wait a second for network initialization
		time.Sleep(1 * time.Second)
		_, totalRules, _, _ := adUpdater.GetStatus()
		if totalRules == 0 {
			log.Println("[Main] Empty local database detected. Proactively triggering background sync...")
			adUpdater.StartUpdate()
		}
	}()

	log.Println("[Main] VortexDNS is now fully operational! Serving queries.")

	// 6. Graceful Shutdown Management
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[Main] Received shutdown signal: %v. Gracefully stopping listeners...", sig)

	// Stop DNS listeners immediately to stop accepting traffic
	dnsServer.Advanced().TeardownTransparentProxy(cfg.BindAddress)
	dnsServer.Shutdown()

	log.Println("[Main] Shutdown completed. Goodbye!")
}

// resetAdminCredentials rewrites the admin login in the config file. It is the
// single recovery path that works identically under systemd, Docker, Podman and
// Kubernetes: run the same binary with -reset-password against the mounted
// config, no external tools required.
//
// The new password is taken, in order, from:
//  1. the VORTEX_ADMIN_PASSWORD environment variable (for non-interactive use:
//     `docker run`, a Kubernetes Job, CI);
//  2. standard input (for interactive use: `docker exec -it`, `kubectl exec -it`,
//     or a piped `echo secret | ...`).
//
// It never echoes the password and never logs it.
func resetAdminCredentials(configPath, newUsername string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config %q: %w", configPath, err)
	}

	password := os.Getenv("VORTEX_ADMIN_PASSWORD")
	source := "env VORTEX_ADMIN_PASSWORD"
	if password == "" {
		// Prompt only when attached to a terminal; when piped, read silently so
		// `echo secret | vortexdns -reset-password` also works.
		if isTerminal(os.Stdin) {
			fmt.Fprint(os.Stderr, "New admin password: ")
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
		source = "stdin"
	}

	// Enforce the same minimum the setup API uses, so recovery can't create a
	// weaker credential than the front door allows.
	if len(password) < 6 {
		return fmt.Errorf("password too short (min 6 chars); provide via VORTEX_ADMIN_PASSWORD or stdin")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	if newUsername != "" {
		cfg.AdminUsername = newUsername
	}
	cfg.AdminPasswordHash = string(hash)

	if err := config.Save(configPath, cfg); err != nil {
		return fmt.Errorf("saving config %q: %w", configPath, err)
	}

	log.Printf("[Reset] Admin credentials updated for user %q (password from %s). Restart VortexDNS to apply.", cfg.AdminUsername, source)
	return nil
}

// isTerminal reports whether f is an interactive terminal, used only to decide
// whether to print a prompt. Avoids a dependency on golang.org/x/term by
// checking the file mode: a character device is a TTY, a pipe or regular file
// is not.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}


// processLogMaxBytes caps the process log. It grows slowly compared to the
// access log, so a single truncation point is enough and no generations are
// kept: the interesting lines are the recent ones.
const processLogMaxBytes = 8 << 20 // 8 MiB

// setupProcessLog sends log output to path in addition to stdout, returning a
// close function. A path of "" leaves logging on stdout alone, which is what
// happens when running directly from a terminal.
func setupProcessLog(path string) func() {
	if path == "" {
		return nil
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[Main] Log directory %q unavailable: %v. Logging to stdout only.", dir, err)
			return nil
		}
	}

	// Truncate rather than append once oversized, keeping the file bounded
	// without a rotation scheme this log does not need.
	if info, err := os.Stat(path); err == nil && info.Size() > processLogMaxBytes {
		if err := os.Truncate(path, 0); err != nil {
			log.Printf("[Main] Could not truncate oversized log %q: %v", path, err)
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("[Main] Cannot open log file %q: %v. Logging to stdout only.", path, err)
		return nil
	}

	// Both destinations: the file for the dashboard's System Log panel, stdout
	// so journalctl still shows output when running under systemd.
	log.SetOutput(io.MultiWriter(os.Stdout, file))

	return func() {
		log.SetOutput(os.Stdout)
		_ = file.Close()
	}
}

func installService(configPath string) {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execPath, _ = filepath.Abs(execPath)
	
	absConfig, _ := filepath.Abs(configPath)
	workDir := filepath.Dir(execPath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=VortexDNS High-Performance Adblocker
After=network.target

[Service]
Type=simple
ExecStart=%s -config %s
WorkingDirectory=%s
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, execPath, absConfig, workDir)

	servicePath := "/etc/systemd/system/vortexdns.service"
	err = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	if err != nil {
		log.Fatalf("Failed to write systemd service: %v", err)
	}

	log.Println("Reloading systemd daemon...")
	exec.Command("systemctl", "daemon-reload").Run()
	
	log.Println("Enabling VortexDNS service on boot...")
	exec.Command("systemctl", "enable", "vortexdns.service").Run()
	
	log.Println("Starting VortexDNS service...")
	exec.Command("systemctl", "start", "vortexdns.service").Run()

	log.Println("Installation complete! VortexDNS (DNS + Web Dashboard) is now running as a service.")
}
