#!/bin/sh

# ==============================================================================
#  VortexDNS - Premium Linux Uninstaller Script
#  Completely removes VortexDNS binary, services, database, configurations,
#  and source code directory.
# ==============================================================================

set -e

# ANSI Color Codes
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

# 1. Check for Root Privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_info "Uninstaller must run with root privileges. Elevating via sudo..."
        exec sudo sh "$0" "$@"
    fi
}

# 2. Stop and Disable Systemd Service
remove_service() {
    log_info "Stopping VortexDNS systemd service if running..."
    if systemctl is-active vortexdns.service >/dev/null 2>&1; then
        systemctl stop vortexdns.service || log_warn "Failed to stop vortexdns.service"
    fi

    log_info "Disabling VortexDNS systemd service..."
    if systemctl is-enabled vortexdns.service >/dev/null 2>&1; then
        systemctl disable vortexdns.service || log_warn "Failed to disable vortexdns.service"
    fi

    log_info "Removing systemd service file..."
    if [ -f /etc/systemd/system/vortexdns.service ]; then
        rm -f /etc/systemd/system/vortexdns.service
        systemctl daemon-reload
        log_success "Systemd service successfully removed."
    else
        log_info "No systemd service file found."
    fi
}

# 3. Restore DNS Stub Listener (systemd-resolved) if modified
restore_dns_stub() {
    if [ -f /etc/systemd/resolved.conf.bak ]; then
        log_info "Restoring backup of systemd-resolved configuration..."
        mv -f /etc/systemd/resolved.conf.bak /etc/systemd/resolved.conf
        systemctl restart systemd-resolved || log_warn "Failed to restart systemd-resolved"
        log_success "systemd-resolved configuration successfully restored."
    fi
}

# 4. Clean Up Binaries & Configuration Directories
remove_files() {
    log_info "Removing installed binaries, configurations, and database directories..."

    # Remove binary
    if [ -f /usr/local/bin/vortexdns ]; then
        rm -f /usr/local/bin/vortexdns
        log_success "Removed: /usr/local/bin/vortexdns"
    fi

    # Remove config
    if [ -d /etc/vortexdns ]; then
        rm -rf /etc/vortexdns
        log_success "Removed configuration folder: /etc/vortexdns"
    fi

    # Remove working dir & databases
    if [ -d /var/lib/vortexdns ]; then
        rm -rf /var/lib/vortexdns
        log_success "Removed library database folder: /var/lib/vortexdns"
    fi
}

# 5. Clean Up Source Code Directory (Background Delayed Deletion)
remove_source_code() {
    SOURCE_DIR="/root/vortexdns"
    if [ -d "$SOURCE_DIR" ]; then
        log_info "Scheduling source code folder deletion: $SOURCE_DIR..."
        
        # We spawn a background subshell with a delay to delete the directory
        # containing this script. This ensures the script finishes execution,
        # outputs status, and exits cleanly before the folder vanishes.
        (
            sleep 0.5
            rm -rf "$SOURCE_DIR"
        ) >/dev/null 2>&1 &
        
        log_success "Scheduled source code directory removal."
    else
        log_info "Source code directory $SOURCE_DIR not found."
    fi
}

# Main Routine
main() {
    printf "${CYAN}======================================================================${RESET}\n"
    printf "${RED}            VortexDNS Server Uninstaller & Cleaner Tool               ${RESET}\n"
    printf "${CYAN}======================================================================${RESET}\n"
    
    check_root "$@"
    remove_service
    restore_dns_stub
    remove_files
    remove_source_code
    
    printf "\n"
    printf "${GREEN}======================================================================${RESET}\n"
    printf "${GREEN} 🎉 VortexDNS Server has been completely uninstalled and cleaned!     ${RESET}\n"
    printf "${GREEN}======================================================================${RESET}\n"
}

main "$@"
