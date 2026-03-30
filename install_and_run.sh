#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  CyberRemedy v1.2 — Install & Run
#  Run this ONCE to install all dependencies, then use startup.sh
#  Usage:  sudo bash install_and_run.sh
# ═══════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠  $*${NC}"; }
err()  { echo -e "${RED}❌ $*${NC}"; }
info() { echo -e "${CYAN}   $*${NC}"; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     CyberRemedy v1.2 — Setup & Launch           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Check root ──────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  warn "Not running as root — live packet capture will be disabled."
  warn "For full capture support: sudo bash install_and_run.sh"
fi

# ── Detect python ───────────────────────────────────────────────────
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
  if command -v "$cmd" &>/dev/null; then
    PYTHON="$cmd"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  err "Python 3 not found. Install with:  sudo apt install python3"
  exit 1
fi
ok "Python: $($PYTHON --version)"

# ── Install system dependencies ──────────────────────────────────────
info "Installing system packages (requires apt)..."
if command -v apt-get &>/dev/null; then
  apt-get update -qq 2>/dev/null || warn "apt update failed — continuing"
  apt-get install -y -qq \
    python3-pip python3-dev libpcap-dev tcpdump \
    libssl-dev libffi-dev build-essential \
    2>/dev/null || warn "Some system packages may not have installed"
  ok "System packages done"
else
  warn "apt not available — skipping system packages (macOS/other OS detected)"
fi

# ── Core pip packages (required) ────────────────────────────────────
info "Installing core Python packages..."
CORE_PKGS=(
  "fastapi==0.111.0"
  "uvicorn[standard]==0.29.0"
  "websockets>=12.0"
  "pydantic>=2.0"
  "pyyaml>=6.0"
  "requests>=2.28"
  "numpy>=1.24"
  "scikit-learn>=1.3"
  "joblib>=1.3"
  "psutil>=5.9"
  "jinja2>=3.1"
  "aiofiles>=23.1"
  "python-dotenv>=1.0"
  "tinydb>=4.8"
  "PyJWT>=2.8"
  "bcrypt>=4.0"
)

for pkg in "${CORE_PKGS[@]}"; do
  if $PYTHON -m pip install "$pkg" --quiet --break-system-packages 2>/dev/null; then
    ok "  $pkg"
  else
    $PYTHON -m pip install "$pkg" --quiet 2>/dev/null && ok "  $pkg" || warn "  Failed: $pkg"
  fi
done

# ── Optional pip packages ────────────────────────────────────────────
info "Installing optional packages..."
OPT_PKGS=(
  "scapy>=2.5"
  "netifaces>=0.11"
  "pandas>=2.0"
  "ruamel.yaml>=0.18"
  "pyarrow>=16.0"
  "scipy>=1.13"
  "cvss>=2.6"
  "packaging>=24.0"
)
for pkg in "${OPT_PKGS[@]}"; do
  $PYTHON -m pip install "$pkg" --quiet --break-system-packages 2>/dev/null \
    || $PYTHON -m pip install "$pkg" --quiet 2>/dev/null \
    || warn "  Optional not installed: $pkg (OK — fallback built-in)"
done

ok "All packages installed"

# ── Verify critical imports ──────────────────────────────────────────
info "Verifying imports..."
$PYTHON -c "import fastapi, uvicorn, pydantic; print('  ✅ fastapi + uvicorn + pydantic OK')" || {
  err "Core imports failed — check pip output above"
  exit 1
}
$PYTHON -c "import yaml, sklearn, numpy, joblib; print('  ✅ yaml + sklearn + numpy + joblib OK')"
$PYTHON -c "import scapy.all; print('  ✅ scapy OK')" 2>/dev/null || warn "  scapy not available — simulation mode will be used"

# ── Set up data directories ──────────────────────────────────────────
info "Creating data directories..."
for d in data data/logs data/logs/alerts data/logs/traffic data/logs/blocks \
          data/logs/events data/logs/assets data/reports data/datasets \
          data/yara_rules data/sigma_rules data/lake/hot data/lake/warm \
          data/lake/cold data/pcap data/geoip data/assets models logs; do
  mkdir -p "$d"
done
ok "Directories created"

# ── Verify ML models ────────────────────────────────────────────────
info "Checking ML models..."
if [ -f "models/anomaly_model.joblib" ] && [ -f "models/rf_attack_model.joblib" ]; then
  ok "ML models present (anomaly_model.joblib + rf_attack_model.joblib)"
else
  warn "ML models missing — will be auto-trained on first startup (takes ~10s)"
fi

# ── Write startup.sh ─────────────────────────────────────────────────
cat > startup.sh << 'RUNEOF'
#!/bin/bash
# CyberRemedy v1.2 — Quick Start (run after install_and_run.sh)
cd "$(dirname "$0")"
PYTHON=$(command -v python3 || command -v python)
echo ""
echo -e "\033[0;36m╔══════════════════════════════════════════════════╗\033[0m"
echo -e "\033[0;36m║     CyberRemedy v1.2 — AI SIEM Platform         ║\033[0m"
echo -e "\033[0;36m╚══════════════════════════════════════════════════╝\033[0m"
echo ""
echo "  Dashboard  →  http://localhost:8000"
echo "  API Docs   →  http://localhost:8000/docs"
echo "  Syslog     →  UDP/TCP :5514"
echo "  WinLog     →  :5515"
echo "  Press Ctrl+C to stop"
echo ""
exec sudo "$PYTHON" main.py "$@"
RUNEOF
chmod +x startup.sh
ok "startup.sh created"

# ── Launch ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Setup complete! Launching CyberRemedy...${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Dashboard →  ${CYAN}http://localhost:8000${NC}"
echo -e "  API Docs  →  ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Press ${RED}Ctrl+C${NC} to stop"
echo ""

exec "$PYTHON" main.py "$@"
