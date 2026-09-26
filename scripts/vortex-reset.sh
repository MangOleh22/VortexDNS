#!/bin/bash
#
# VortexDNS credential reset — one mechanism for every deployment target.
#
# All hashing is delegated to the vortexdns binary's `-reset-password` flag, so
# this script needs no python or bcrypt on the host. That is what lets the exact
# same recovery work on bare metal, Docker, Podman and Kubernetes.
#
# Usage:
#   ./vortex-reset.sh                      # interactive menu
#   VORTEX_ADMIN_PASSWORD=secret ./vortex-reset.sh --password   # non-interactive

set -euo pipefail

cyan="\033[36m"; green="\033[32m"; yellow="\033[33m"; red="\033[31m"; bold="\033[1m"; reset="\033[0m"

# Locate the binary: installed host location, container location, then PATH.
find_binary() {
  for c in /usr/local/bin/vortexdns /app/vortexdns "$(dirname "$0")/../vortexdns" "$(dirname "$0")/../vortexdns_build"; do
    if [ -x "$c" ]; then echo "$c"; return 0; fi
  done
  command -v vortexdns 2>/dev/null && return 0
  return 1
}

# Locate the config the running server uses (host paths, then container).
find_config() {
  for c in /etc/vortexdns/config.json /app/config.json /root/vortexdns/config.json "$(dirname "$0")/../config.json" ./config.json; do
    if [ -f "$c" ]; then echo "$c"; return 0; fi
  done
  return 1
}

BIN=$(find_binary) || { echo -e "${red}✗ vortexdns binary tidak ditemukan${reset}"; exit 1; }
CONFIG=$(find_config) || { echo -e "${red}✗ config.json tidak ditemukan${reset}"; exit 1; }

# Restart the server so the new hash takes effect, using whatever supervisor is
# present. In a container there is usually none: the orchestrator restarts the
# process, so a missing systemctl is not an error.
restart_server() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files vortexdns.service >/dev/null 2>&1; then
    systemctl restart vortexdns && echo -e "${green}  ✓ Service di-restart${reset}"
  else
    echo -e "${yellow}  ⚠ Tidak ada systemd service. Restart container/proses VortexDNS agar berlaku.${reset}"
  fi
}

do_reset() {
  local user_flag=("$@")
  # The binary reads the password from VORTEX_ADMIN_PASSWORD or stdin and does
  # the bcrypt hashing; we never touch the hash here.
  "$BIN" -reset-password -config "$CONFIG" "${user_flag[@]}"
  restart_server
}

banner() {
  echo -e "${cyan}"
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║   VortexDNS - User Management CLI    ║"
  echo "  ╚══════════════════════════════════════╝"
  echo -e "${reset}"
  echo -e "  Binary : ${bold}${BIN}${reset}"
  echo -e "  Config : ${bold}${CONFIG}${reset}"
  echo -e "  User   : ${bold}${green}$(grep -o '"admin_username":[[:space:]]*"[^"]*"' "$CONFIG" | sed 's/.*"\([^"]*\)"$/\1/')${reset}"
  echo ""
}

# Non-interactive mode: `--password` with VORTEX_ADMIN_PASSWORD set. For CI,
# docker run, kubectl exec -- ... without a TTY.
if [ "${1:-}" = "--password" ]; then
  do_reset
  exit 0
fi

banner
echo "  [1] Ganti password"
echo "  [2] Ganti username + password"
echo "  [0] Keluar"
echo ""
read -rp "  Pilih [0-2]: " choice
echo ""

case "$choice" in
  1) do_reset ;;
  2) read -rp "  Username baru: " newuser
     [ -z "$newuser" ] && { echo -e "${red}  ✗ Username kosong${reset}"; exit 1; }
     do_reset -reset-username "$newuser" ;;
  0) echo "  Bye!" ;;
  *) echo -e "${red}  ✗ Pilihan tidak valid${reset}" ;;
esac
echo ""
