#!/usr/bin/env bash
# EdgeWalker Installer
# --------------------
# Local:   bash scripts/install.sh
# Remote:  curl -sSL https://raw.githubusercontent.com/periphery-security/edgewalker/main/scripts/install.sh | bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

echo
echo -e "${CYAN}EdgeWalker Installer${NC}"
echo "===================="
echo

# -- Check Python 3.9+ ---------------------------------------------------

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Python 3 not found.${NC}"
    echo "  macOS:   brew install python3"
    echo "  Ubuntu:  sudo apt install python3 python3-pip"
    echo "  Other:   https://python.org/downloads"
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
    echo -e "${RED}Python 3.9+ required (found $PY_VERSION)${NC}"
    exit 1
fi

echo -e "  Python $PY_VERSION  ${GREEN}OK${NC}"

# -- Check nmap -----------------------------------------------------------

if command -v nmap &>/dev/null; then
    NMAP_VERSION=$(nmap --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    echo -e "  nmap $NMAP_VERSION    ${GREEN}OK${NC}"
else
    echo -e "  nmap       ${DIM}not found -- installing...${NC}"
    if [[ "$OSTYPE" == darwin* ]]; then
        if command -v brew &>/dev/null; then
            brew install nmap --quiet
        else
            echo -e "${RED}Homebrew not found. Install nmap manually: brew install nmap${NC}"
            exit 1
        fi
    elif command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq nmap
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q nmap
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap
    else
        echo -e "${RED}Could not detect package manager. Install nmap manually.${NC}"
        exit 1
    fi

    if command -v nmap &>/dev/null; then
        NMAP_VERSION=$(nmap --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        echo -e "  nmap $NMAP_VERSION    ${GREEN}OK${NC}"
    else
        echo -e "${RED}nmap installation failed. Install it manually and re-run.${NC}"
        exit 1
    fi
fi

# -- Check / install pipx ------------------------------------------------

# Check pipx actually works (not just that a binary exists on PATH)
if ! pipx --version &>/dev/null; then
    echo
    echo "  pipx not found -- installing..."
    python3 -m pip install --user pipx --quiet &>/dev/null \
        || python3 -m pip install --break-system-packages --user pipx --quiet &>/dev/null \
        || true
    python3 -m pipx ensurepath &>/dev/null || true

    # Make pipx available in this session (covers Linux + macOS user paths)
    export PATH="$HOME/.local/bin:$PATH"
    PYUSERBASE=$(python3 -m site --user-base 2>/dev/null || true)
    if [ -n "$PYUSERBASE" ]; then
        export PATH="$PYUSERBASE/bin:$PATH"
    fi

    if ! pipx --version &>/dev/null; then
        # Fall back to running as module
        if python3 -m pipx --version &>/dev/null; then
            pipx() { python3 -m pipx "$@"; }
        else
            echo -e "${RED}Failed to install pipx.${NC}"
            echo "  Install manually: python3 -m pip install --user pipx"
            exit 1
        fi
    fi
fi

echo -e "  pipx       ${GREEN}OK${NC}"
echo

# -- Install EdgeWalker ---------------------------------------------------

echo "Installing EdgeWalker..."
echo

# Remove any previous edgewalker install (root or user) to avoid stale PATH conflicts
# pipx uninstall edgewalker &>/dev/null || true
pipx uninstall git++https://github.com/periphery-security/edgewalker.git &>/dev/null || true
if [ -n "$SUDO_USER" ]; then
    # Running as root — also clean the invoking user's pipx install
    # Use python3 to safely resolve the home directory (avoids eval injection)
    USER_HOME=$(python3 -c "import os, pwd; print(pwd.getpwnam(os.environ.get('SUDO_USER')).pw_dir)" 2>/dev/null || true)
    if [ -n "$USER_HOME" ] && [ "$USER_HOME" != "/" ]; then
        sudo rm -rf "$USER_HOME/.local/pipx/venvs/edgewalker" 2>/dev/null || true
        sudo rm -f  "$USER_HOME/.local/bin/edgewalker" 2>/dev/null || true
    fi
fi
PIPX_VENV="$HOME/.local/pipx/venvs/edgewalker"
if [ -d "$PIPX_VENV" ]; then
    sudo rm -rf "$PIPX_VENV" 2>/dev/null || true
fi

# Resolve project root (one level up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)"

# Clean stale build artifacts so pip builds from source
if [ -n "$PROJECT_DIR" ]; then
    rm -rf "$PROJECT_DIR/build" "$PROJECT_DIR"/*.egg-info 2>/dev/null \
        || sudo rm -rf "$PROJECT_DIR/build" "$PROJECT_DIR"/*.egg-info 2>/dev/null \
        || true
fi

PIPX_LOG=$(mktemp)
if [ -n "$PROJECT_DIR" ] && [ -f "$PROJECT_DIR/pyproject.toml" ]; then
    # Local install from repo (--no-cache-dir forces a fresh build)
    pipx install "$PROJECT_DIR" --force --pip-args="--no-cache-dir" &>"$PIPX_LOG" || true
else
    # Remote install from PyPI
    pipx install edgewalker --force &>"$PIPX_LOG" || true
fi

# Verify it worked
if ! command -v edgewalker &>/dev/null; then
    # pipx bin dir might not be on PATH yet
    export PATH="$HOME/.local/bin:$PATH"
fi

if command -v edgewalker &>/dev/null; then
    echo -e "${GREEN}EdgeWalker installed successfully!${NC}"
else
    echo -e "${RED}Installation failed.${NC}"
    echo
    # Show the log so the user can diagnose
    cat "$PIPX_LOG" 2>/dev/null
    rm -f "$PIPX_LOG"
    exit 1
fi
rm -f "$PIPX_LOG"

# -- Apply nmap capabilities (Linux only) --------------------------------

if [[ "$OSTYPE" == linux* ]]; then
    NMAP_PATH=$(which nmap)
    if [ -n "$NMAP_PATH" ]; then
        echo
        echo "Applying nmap capabilities (requires sudo)..."
        sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH" || echo -e "${RED}Failed to apply capabilities.${NC}"
    fi
fi

echo
if [[ "$OSTYPE" == linux* ]]; then
    echo "  Run:         edgewalker"
else
    echo "  Run:         sudo edgewalker"
fi
echo "  Full Uninstall: bash scripts/uninstall.sh"
echo -e "  (pipx uninstall edgewalker only removes the package, not your data)"
echo
