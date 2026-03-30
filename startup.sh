#!/usr/bin/env bash
# =============================================================================
# CyberRemedy — DHCP-aware startup script
# =============================================================================
# Use this instead of "python3 main.py" directly.
# Resolves DHCP gateway, enables IP forwarding, optional ARP scan for targets.
#
# Usage:
#   sudo bash startup.sh              # standard start
#   sudo bash startup.sh --scan       # ARP scan + auto-populate targets
#   sudo bash startup.sh --iface wlan0 --mon wlan1   # override adapters
# =============================================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$SCRIPT_DIR/config/settings.yaml"
PYTHON="${PYTHON:-python3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[OK]${RESET} $*"; }
info() { echo -e "${CYAN}[..] $*${RESET}"; }
warn() { echo -e "${YELLOW}[!!] $*${RESET}"; }
err()  { echo -e "${RED}[XX] $*${RESET}"; }

echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   CyberRemedy — DHCP-aware startup           ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Must run as root ────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    err "Must run as root.  Use:  sudo bash startup.sh"
    exit 1
fi
ok "Running as root"

# ── Parse flags ─────────────────────────────────────────────────────────────
CONNECTED_IFACE=""
MONITOR_IFACE=""
DO_SCAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)  CONNECTED_IFACE="$2"; shift 2 ;;
        --mon)    MONITOR_IFACE="$2";   shift 2 ;;
        --scan)   DO_SCAN=true;         shift   ;;
        *) shift ;;
    esac
done

# ── Detect connected interface ───────────────────────────────────────────────
if [[ -z "$CONNECTED_IFACE" ]]; then
    CONNECTED_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
fi
if [[ -z "$CONNECTED_IFACE" ]]; then
    err "Cannot detect connected interface.  Try: sudo bash startup.sh --iface wlan0"
    exit 1
fi
ok "Connected interface : $CONNECTED_IFACE"

# ── Read current DHCP gateway ───────────────────────────────────────────────
GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
if [[ -z "$GATEWAY" ]]; then
    err "Cannot detect gateway — is the network up?"
    exit 1
fi
ok "DHCP gateway        : $GATEWAY"

# ── Get this machine's IP ────────────────────────────────────────────────────
MY_IP=$(ip -4 addr show "$CONNECTED_IFACE" 2>/dev/null \
    | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
SUBNET_BASE=$(echo "$MY_IP" | cut -d'.' -f1-3)
ok "This machine IP     : $MY_IP  (subnet $SUBNET_BASE.0/24)"

# ── Enable IP forwarding (required for MITM to work) ────────────────────────
echo 1 > /proc/sys/net/ipv4/ip_forward
ok "IP forwarding enabled"
# Persist across reboots
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    ok "IP forwarding persisted to /etc/sysctl.conf"
fi

# ── Check packages ───────────────────────────────────────────────────────────
info "Checking required tools..."
for tool in airmon-ng tcpdump iw; do
    if ! command -v "$tool" &>/dev/null; then
        warn "Missing: $tool  →  sudo apt install aircrack-ng tcpdump iw"
    fi
done
if $PYTHON -c "from scapy.all import ARP" 2>/dev/null; then
    ok "scapy OK"
else
    warn "scapy missing — MITM will use tcpdump fallback"
    warn "Fix: pip install scapy --break-system-packages"
fi

# ── Write current DHCP gateway into settings.yaml ───────────────────────────
# gateway_ip is left blank in config — we write the live value here so
# MITM always uses the correct gateway even after DHCP lease renewal.
$PYTHON - "$SETTINGS" "$GATEWAY" <<'PYEOF'
import sys, re
settings_path, gw = sys.argv[1], sys.argv[2]
with open(settings_path) as f:
    content = f.read()
content = re.sub(
    r'(^\s*gateway_ip:\s*).*',
    f'  gateway_ip: "{gw}"  # set by startup.sh',
    content,
    flags=re.MULTILINE
)
with open(settings_path, "w") as f:
    f.write(content)
print(f"  gateway_ip written: {gw}")
PYEOF
ok "settings.yaml: gateway_ip = $GATEWAY"

# ── Optional ARP scan to discover targets ────────────────────────────────────
if $DO_SCAN; then
    info "Scanning $SUBNET_BASE.0/24 for devices (~5 seconds)..."
    DISCOVERED=()

    if command -v arp-scan &>/dev/null; then
        while IFS= read -r line; do
            IP=$(echo "$line" | awk '{print $1}')
            if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
               && [[ "$IP" != "$GATEWAY" ]] && [[ "$IP" != "$MY_IP" ]]; then
                DISCOVERED+=("$IP")
            fi
        done < <(arp-scan --localnet --interface="$CONNECTED_IFACE" 2>/dev/null | grep -E '^\d')
    else
        # Ping sweep fallback
        info "arp-scan not found — ping sweep (slower)"
        for i in $(seq 1 254); do
            ping -c1 -W1 "$SUBNET_BASE.$i" &>/dev/null &
        done
        wait
        while IFS= read -r line; do
            IP=$(echo "$line" | awk '{print $1}')
            if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
               && [[ "$IP" != "$GATEWAY" ]] && [[ "$IP" != "$MY_IP" ]]; then
                DISCOVERED+=("$IP")
            fi
        done < <(arp -n 2>/dev/null | grep -v "incomplete" | tail -n +2)
    fi

    if [[ ${#DISCOVERED[@]} -gt 0 ]]; then
        ok "Discovered ${#DISCOVERED[@]} device(s): ${DISCOVERED[*]}"
        # Inject discovered IPs into settings.yaml active_targets
        JOINED=$(printf '"%s"\n' "${DISCOVERED[@]}" | paste -sd,)
        $PYTHON - "$SETTINGS" "${DISCOVERED[@]}" <<'PYEOF'
import sys, re, yaml
settings_path = sys.argv[1]
ips = sys.argv[2:]
with open(settings_path) as f:
    content = f.read()
# Replace active_targets block
targets_block = "\n".join(f'    - "{ip}"' for ip in ips)
content = re.sub(
    r'(\s*active_targets:\s*)(\[\].*|\n(?:[ \t]+-[^\n]*\n)*)',
    f'\n  active_targets:\n{targets_block}\n',
    content
)
with open(settings_path, "w") as f:
    f.write(content)
print(f"  active_targets: {ips}")
PYEOF
        ok "settings.yaml: active_targets populated"
    else
        warn "No devices found — add targets live after start:"
        warn "  curl -s -X POST http://localhost:8000/api/siem/active/target/add \\"
        warn "       -H 'Content-Type: application/json' -d '{\"ip\": \"DEVICE_IP\"}'"
    fi
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─── Configuration ────────────────────────────────────${RESET}"
echo "   Connected iface  : $CONNECTED_IFACE  (IP: $MY_IP)"
echo "   DHCP gateway     : $GATEWAY"
echo "   Subnet           : $SUBNET_BASE.0/24"
[[ -n "$MONITOR_IFACE" ]] && echo "   Monitor iface    : $MONITOR_IFACE"
echo ""
echo -e "${BOLD}─── Add targets live at any time: ────────────────────${RESET}"
echo "   curl -s -X POST http://localhost:8000/api/siem/active/target/add \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -d '{\"ip\": \"DEVICE_IP\"}'"
echo ""
echo -e "${BOLD}─── Starting CyberRemedy ─────────────────────────────${RESET}"
echo ""

cd "$SCRIPT_DIR"
exec $PYTHON main.py
