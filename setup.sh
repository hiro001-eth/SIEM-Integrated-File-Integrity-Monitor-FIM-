#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# SIEM-Integrated File Integrity Monitor — One-Click Setup Script
# ══════════════════════════════════════════════════════════════════════════════
# This script sets up EVERYTHING automatically:
#   1. Installs Python dependencies
#   2. Creates the monitored/ test directory
#   3. Starts Docker Compose (Elasticsearch + Kibana + FIM)
#   4. Builds the baseline
#   5. Shows you how to use it
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${BOLD}SIEM File Integrity Monitor — Setup Script${NC}                 ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Check prerequisites ─────────────────────────────────────────────
echo -e "${CYAN}[1/6]${NC} Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
    echo -e "  ${RED}✗${NC} Python3 not found. Please install Python 3.10+"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python3: $(python3 --version 2>&1)"

if ! command -v pip &>/dev/null && ! command -v pip3 &>/dev/null; then
    echo -e "  ${RED}✗${NC} pip not found. Please install pip."
    exit 1
fi
echo -e "  ${GREEN}✓${NC} pip: $(pip --version 2>&1 | head -1)"

DOCKER_OK=true
if ! command -v docker &>/dev/null; then
    echo -e "  ${YELLOW}!${NC} Docker not found. Docker Compose will be skipped."
    DOCKER_OK=false
else
    echo -e "  ${GREEN}✓${NC} Docker: $(docker --version 2>&1)"
fi

if ! command -v docker compose &>/dev/null 2>&1 && ! docker compose version &>/dev/null 2>&1; then
    echo -e "  ${YELLOW}!${NC} Docker Compose not found. Docker Compose will be skipped."
    DOCKER_OK=false
else
    echo -e "  ${GREEN}✓${NC} Docker Compose: $(docker compose version 2>&1 | head -1)"
fi

# ── Step 2: Install Python dependencies ─────────────────────────────────────
echo ""
echo -e "${CYAN}[2/6]${NC} Installing Python dependencies..."
pip install -r requirements.txt --quiet 2>&1
pip install -r requirements-dev.txt --quiet 2>&1
echo -e "  ${GREEN}✓${NC} All dependencies installed (watchdog, elasticsearch, rich, Flask, pytest)"

# ── Step 3: Make scripts executable ──────────────────────────────────────────
echo ""
echo -e "${CYAN}[3/6]${NC} Making scripts executable..."
chmod +x monitor.py dashboard.py 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} monitor.py and dashboard.py are now executable"

# ── Step 4: Create monitored directory for Docker ───────────────────────────
echo ""
echo -e "${CYAN}[4/6]${NC} Creating test directory..."
mkdir -p monitored
echo "This is a test file for the FIM." > monitored/test_file.txt
echo "Configuration data here." > monitored/config.ini
echo '{"key": "value"}' > monitored/data.json
echo -e "  ${GREEN}✓${NC} Created monitored/ with 3 sample files"

# ── Step 5: Build baseline (local, for /tmp as a safe test) ─────────────────
echo ""
echo -e "${CYAN}[5/6]${NC} Building baseline for test directory..."
python3 monitor.py --baseline --paths ./monitored --no-tui 2>&1 | tail -3
echo -e "  ${GREEN}✓${NC} Baseline built for monitored/"

# ── Step 6: Docker Compose ──────────────────────────────────────────────────
echo ""
if [ "$DOCKER_OK" = true ]; then
    echo -e "${CYAN}[6/6]${NC} Starting Docker Compose (Elasticsearch + Kibana + FIM)..."
    echo -e "  ${YELLOW}Note:${NC} First run downloads ~1.5GB of Docker images. Be patient."
    echo ""

    # Check if Docker daemon is running
    if ! docker info &>/dev/null 2>&1; then
        echo -e "  ${YELLOW}!${NC} Docker daemon is not running."
        echo -e "  ${YELLOW}!${NC} Start it with: ${BOLD}sudo systemctl start docker${NC}"
        echo -e "  ${YELLOW}!${NC} Then run: ${BOLD}docker compose up -d${NC}"
    else
        docker compose up -d 2>&1
        echo ""
        echo -e "  ${GREEN}✓${NC} Docker Compose started!"
        echo -e "  ${GREEN}✓${NC} Elasticsearch: http://localhost:9200"
        echo -e "  ${GREEN}✓${NC} Kibana:        http://localhost:5601  (may take 1-2 min to start)"
    fi
else
    echo -e "${CYAN}[6/6]${NC} Skipping Docker (not installed)"
    echo -e "  ${YELLOW}!${NC} You can still use the FIM locally without Docker."
    echo -e "  ${YELLOW}!${NC} Events will be saved to ${BOLD}fim.log${NC} instead of Elasticsearch."
fi

# ── Done! Show usage guide ──────────────────────────────────────────────────
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup Complete!${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Quick Commands:${NC}"
echo ""
echo -e "  ${CYAN}# Start real-time monitoring (with Rich TUI dashboard)${NC}"
echo -e "  ${BOLD}python3 monitor.py --watch --paths ./monitored${NC}"
echo ""
echo -e "  ${CYAN}# Build/rebuild the file hash baseline${NC}"
echo -e "  ${BOLD}python3 monitor.py --baseline --paths ./monitored${NC}"
echo ""
echo -e "  ${CYAN}# Run a one-time integrity scan${NC}"
echo -e "  ${BOLD}python3 monitor.py --scan --paths ./monitored${NC}"
echo ""
echo -e "  ${CYAN}# View stored baseline data${NC}"
echo -e "  ${BOLD}python3 monitor.py --show${NC}"
echo ""
echo -e "  ${CYAN}# View event log (when ES is down)${NC}"
echo -e "  ${BOLD}python3 monitor.py --show-log${NC}"
echo ""
echo -e "  ${CYAN}# Start web dashboard${NC}"
echo -e "  ${BOLD}python3 dashboard.py${NC}"
echo ""
echo -e "  ${CYAN}# Run all tests${NC}"
echo -e "  ${BOLD}python3 -m pytest tests/ -v${NC}"
echo ""
echo -e "  ${CYAN}# Docker Compose commands${NC}"
echo -e "  ${BOLD}docker compose up -d${NC}        # Start ELK stack"
echo -e "  ${BOLD}docker compose logs -f fim${NC}  # View FIM logs"
echo -e "  ${BOLD}docker compose down${NC}         # Stop everything"
echo ""
echo -e "  ${CYAN}# Configuration${NC}"
echo -e "  Edit ${BOLD}.env${NC} to configure email alerts, webhooks, and ES connection."
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
