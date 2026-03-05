#!/bin/bash
# CyberRemedy v1.0 Startup Script

cd "$(dirname "$0")"

echo "========================================="
echo "  AID-ARS v4.0 — AI SIEM Platform"
echo "========================================="
echo ""
echo "Dashboard:    http://localhost:8000"
echo "API Docs:     http://localhost:8000/docs"
echo "Syslog UDP:   :5514"
echo "Syslog TCP:   :5514"
echo "WinLog port:  :5515"
echo "Agent port:   :5516"
echo ""

# Activate venv if present
[ -d "siem_ultra" ] && source siem_ultra/bin/activate

python main.py "$@"
