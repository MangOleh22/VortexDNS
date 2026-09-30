#!/bin/sh

# ==============================================================================
#  VortexDNS - Premium Linux Installer Script
#  Supports: x86_64, i386, arm64, armv7, riscv64
# ==============================================================================

set -e

# ANSI Color Codes for Premium Output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GOLD='\033[0;33m'
RESET='\033[0m'

log_info() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

log_warn() {
    printf "${GOLD}[WARN]${RESET} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${RESET} %s\n" "$1" 1>&2
    exit 1
}

# 1. Print Welcome Banner
print_banner() {
    printf "${CYAN}"
    printf "   _  __           __            ___  _  ______\n"
    printf "  | |/ /__  ______/ /____ __ __ / _ \\/ |/ / __/\n"
    printf "  |  // _ \\/ __/ __/ __/\\ \\ // // // /    /\\ \\  \n"
    printf "  |_/ \\___/_/  \\__/\\__/ /_\\_\\\\_,_/___/_/|_/___/  v1.2.0\n"
    printf "  High-Performance Adblocking DNS Server - Linux Installer\n"
    printf "${RESET}\n"
}

# 2. Check for Root Privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_info "Installer must run with root privileges. Elevating via sudo..."
        exec sudo sh "$0" "$@"
    fi
}

# 3. Detect OS & CPU Architecture
detect_system() {
    log_info "Detecting system environment..."
    
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    if [ "$OS" != "linux" ]; then
        log_error "VortexDNS only supports Linux operating systems."
    fi

    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)
            GOARCH="amd64"
            ;;
        i386|i486|i686|x86)
            GOARCH="386"
            ;;
        aarch64|arm64)
            GOARCH="arm64"
            ;;
        armv7l|armv6l|arm)
            GOARCH="arm"
            ;;
        riscv64)
            GOARCH="riscv64"
            ;;
        *)
            log_error "Unsupported CPU architecture: $ARCH"
            ;;
    esac

    log_success "Target System: Linux / $ARCH (Go Architecture: $GOARCH)"
}

# 4. Check for and Setup Go Compiler
check_compiler() {
    log_info "Checking for Go compiler..."
    
    if ! command -v go >/dev/null 2>&1; then
        log_warn "Go is not installed on this system. Attempting to download and configure Go..."
        
        # Check for curl or wget
        if command -v curl >/dev/null 2>&1; then
            DL_CMD="curl -sL"
        elif command -v wget >/dev/null 2>&1; then
            DL_CMD="wget -qO-"
        else
            log_error "Either curl or wget is required to download Go dependencies."
        fi

        GO_VERSION="1.21.5"
        GO_TAR="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
        GO_URL="https://go.dev/dl/${GO_TAR}"
        
        log_info "Downloading Go v${GO_VERSION} from ${GO_URL}..."
        mkdir -p /tmp/go-install
        if ! $DL_CMD "$GO_URL" > /tmp/go-install/go.tar.gz; then
            log_error "Failed to download Go compiler toolchain."
        fi

        log_info "Extracting Go toolchain to /usr/local..."
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go-install/go.tar.gz
        rm -rf /tmp/go-install

        export PATH=$PATH:/usr/local/go/bin
        log_success "Go compiler installed successfully at /usr/local/go"
    else
        log_success "Found local Go: $(go version)"
    fi
}

# 5. Build VortexDNS Binary
build_binary() {
    log_info "Compiling VortexDNS for host architecture ($GOARCH)..."
    
    # Locate main.go (relative to scripts/ folder, which is in parent folder)
    SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    if [ ! -f "${SRC_DIR}/main.go" ]; then
        log_error "Could not locate main.go in ${SRC_DIR}. Please run the script from the scripts directory."
    fi

    (
        cd "$SRC_DIR"
        export GOOS=linux
        export GOARCH="$GOARCH"
        export CGO_ENABLED=0
        
        log_info "Running Go build..."
        go build -ldflags="-s -w" -o vortexdns main.go
    )

    if [ ! -f "${SRC_DIR}/vortexdns" ]; then
        log_error "Compilation failed. Binary was not generated."
    fi

    log_success "VortexDNS compiled successfully."
}

# 6. Install Files and Configure Directories
install_files() {
    log_info "Installing VortexDNS binaries and assets..."

    SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    
    # Binary
    cp "${SRC_DIR}/vortexdns" /usr/local/bin/vortexdns
    chmod 755 /usr/local/bin/vortexdns
    
    # Configuration
    mkdir -p /etc/vortexdns
    if [ ! -f /etc/vortexdns/config.json ]; then
        if [ -f "${SRC_DIR}/config.json" ]; then
            cp "${SRC_DIR}/config.json" /etc/vortexdns/config.json
        else
            # Fallback default configuration
            log_info "Creating default configuration file..."
            cat <<EOF > /etc/vortexdns/config.json
{
  "bind_address": ":53",
  "upstream_servers": [
    "1.1.1.1:53",
    "8.8.8.8:53"
  ],
  "blocklist_urls": [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  ],
  "custom_blacklist": [],
  "custom_whitelist": [],
  "dashboard_address": "0.0.0.0:8080",
  "cache_size": 50000,
  "cache_min_ttl": 60,
  "cache_max_ttl": 86400,
  "cache_prefetch": true,
  "rate_limit_qps": 0,
  "blocking_mode": "nxdomain",
  "whitelist_urls": [],
  "database_dir": "vortex_db",
  "admin_username": "",
  "admin_password_hash": "",
  "session_secret": "vortex-secret-change-me",
  "reverse_dns_enabled": true,
  "whois_enabled": true,
  "safe_browsing_enabled": true,
  "parental_control_enabled": true,
  "doh_enabled": false,
  "doh_address": ":8443",
  "dot_enabled": false,
  "dot_address": ":853",
  "doq_enabled": false,
  "doq_address": ":854",
  "dnssec_enabled": true,
  "recursive_resolver": true,
  "dns64_enabled": false,
  "dnstap_enabled": false,
  "as112_enabled": true,
  "chaos_enabled": true,
  "prometheus_enabled": true,
  "split_horizon": {},
  "kubernetes_enabled": false,
  "hosts_file_enabled": true,
  "failover_upstreams": ["8.8.4.4:53"],
  "zone_records": [],
  "block_page_enabled": true,
  "dns_rebinding_enabled": true,
  "drop_requests": [],
  "filter_aaaa": false,
  "geo_dns": true,
  "long_term_stats": true,
  "dhcp_enabled": false,
  "dhcp_range": "192.168.1.100-192.168.1.200"
}
EOF
        fi
    fi
    chmod 644 /etc/vortexdns/config.json

    # Data library folder
    mkdir -p /var/lib/vortexdns
    chmod 755 /var/lib/vortexdns

    # Install vortex-reset user management CLI
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${SCRIPT_DIR}/vortex-reset.sh" ]; then
        cp "${SCRIPT_DIR}/vortex-reset.sh" /usr/local/bin/vortex-reset
        chmod 755 /usr/local/bin/vortex-reset
        log_success "vortex-reset CLI tool installed to /usr/local/bin/vortex-reset"
    fi

    log_success "Files successfully placed in target directories."
}

# 7. Configure Systemd Service
configure_service() {
    log_info "Configuring systemd service..."

    mkdir -p /var/log/vortexdns

    cat <<EOF > /etc/systemd/system/vortexdns.service
[Unit]
Description=VortexDNS High-Performance Adblocking DNS Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/vortexdns
ExecStart=/usr/local/bin/vortexdns -config /etc/vortexdns/config.json
StandardOutput=append:/var/log/vortexdns/vortex.log
StandardError=append:/var/log/vortexdns/vortex.log
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/vortexdns.service
    
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    log_info "Enabling VortexDNS service on boot..."
    systemctl enable vortexdns.service

    log_success "Systemd service configured successfully."
}

# 8. Start and Report Status
start_service() {
    log_info "Starting VortexDNS service..."
    
    # Stop local systemd-resolved DNS stub listener if active to avoid port 53 bind conflicts
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        log_warn "systemd-resolved service detected. To prevent port 53 bind conflicts, disabling DNS Stub Listener..."
        # Backup resolved.conf
        if [ -f /etc/systemd/resolved.conf ]; then
            cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak
            sed -i 's/#DNSStubListener=yes/DNSStubListener=no/g' /etc/systemd/resolved.conf
            sed -i 's/DNSStubListener=yes/DNSStubListener=no/g' /etc/systemd/resolved.conf
            systemctl restart systemd-resolved
        fi
    fi

    systemctl start vortexdns.service
    
    sleep 1.5
    if systemctl is-active vortexdns.service >/dev/null 2>&1; then
        log_success "VortexDNS service is active and running!"
    else
        log_error "VortexDNS failed to start. Run 'journalctl -u vortexdns' to view logs."
    fi
}

# 9. Main Routine
main() {
    print_banner
    check_root "$@"
    detect_system
    check_compiler
    build_binary
    install_files
    configure_service
    start_service
    
    printf "\n"
    printf "${GREEN}======================================================================${RESET}\n"
    printf "${GOLD} 🎉 VortexDNS v1.2.0-Premium Has Been Successfully Installed!${RESET}\n"
    printf "${GREEN}======================================================================${RESET}\n"
    printf " • Binari:            /usr/local/bin/vortexdns\n"
    printf " • Konfigurasi:       /etc/vortexdns/config.json\n"
    printf " • Dashboard UI:      http://localhost:8080 (Buka di browser Anda untuk setup pertama kali)\n"
    printf " • Port DNS Utama:    Port 53 (atau port default pada bind_address)\n"
    printf "\n"
    printf " Kelola servis menggunakan perintah:\n"
    printf "   • Start:   systemctl start vortexdns\n"
    printf "   • Stop:    systemctl stop vortexdns\n"
    printf "   • Status:  systemctl status vortexdns\n"
    printf "   • Logs:    journalctl -u vortexdns -f\n"
    printf "   • Reset:   vortex-reset  (reset/ganti username & password)\n"
    printf "${GREEN}======================================================================${RESET}\n"
}

main "$@"
