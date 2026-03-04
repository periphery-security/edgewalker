#!/usr/bin/env bash
# EdgeWalker Uninstaller
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

echo
echo -e "${CYAN}EdgeWalker Uninstaller${NC}"
echo "======================"
echo

# Ensure pipx is on PATH (same logic as installer)
export PATH="$HOME/.local/bin:$PATH"
PYUSERBASE=$(python3 -m site --user-base 2>/dev/null || true)
if [ -n "$PYUSERBASE" ]; then
    export PATH="$PYUSERBASE/bin:$PATH"
fi

# -- 1. Remove the package ---------------------------------------------------

if command -v pipx &>/dev/null; then
    pipx uninstall edgewalker &>/dev/null && echo -e "  Package removed     ${GREEN}OK${NC}" \
        || echo -e "  Package not installed  ${DIM}skipped${NC}"
elif python3 -m pipx --version &>/dev/null; then
    python3 -m pipx uninstall edgewalker &>/dev/null && echo -e "  Package removed     ${GREEN}OK${NC}" \
        || echo -e "  Package not installed  ${DIM}skipped${NC}"
else
    pip uninstall edgewalker -y &>/dev/null && echo -e "  Package removed     ${GREEN}OK${NC}" \
        || echo -e "  Package not installed  ${DIM}skipped${NC}"
fi

# -- 2. Clean up data EdgeWalker created ---------------------------------

echo
echo -e "${CYAN}Data Cleanup${NC}"
echo "============"

prompt_remove() {
    local path=$1
    local desc=$2
    if [ -d "$path" ]; then
        echo -ne "  Remove $desc? ($path) [y/N] "
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            rm -rf "$path"
            echo -e "  ${DIM}$path${NC}  ${GREEN}removed${NC}"
            return 0
        else
            echo -e "  ${DIM}$path${NC}  ${DIM}kept${NC}"
            return 1
        fi
    fi
    return 1
}

# Get platform-specific paths via Python (same logic as the app)
CONFIG_DIR=$(python3 -c 'from platformdirs import user_config_dir; print(user_config_dir("edgewalker"))' 2>/dev/null || true)
CACHE_DIR=$(python3 -c 'from platformdirs import user_cache_dir; print(user_cache_dir("edgewalker"))' 2>/dev/null || true)

# Global configuration and scan results
if [ -n "$CONFIG_DIR" ]; then
    prompt_remove "$CONFIG_DIR" "configuration and scan results"
fi

# Cached vendor data
if [ -n "$CACHE_DIR" ]; then
    prompt_remove "$CACHE_DIR" "cached vendor data"
fi

# Legacy cleanup (for users migrating from older versions)
prompt_remove "$HOME/.edgewalker" "legacy global configuration"

# Resolve project root (one level up from scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)"

# .edgewalker/ in project root (legacy session_id, optin flag)
prompt_remove "$PROJECT_DIR/.edgewalker" "legacy local session configuration"

# results/ in project root (legacy scan output JSON files)
prompt_remove "$PROJECT_DIR/results" "legacy scan results"

# -- 3. Clean build artifacts ------------------------------------------------

echo
echo -e "${CYAN}Cleaning build artifacts...${NC}"

CLEANED=0

# build/ directory (setuptools intermediate output)
if [ -d "$PROJECT_DIR/build" ]; then
    rm -rf "$PROJECT_DIR/build" 2>/dev/null \
        || sudo rm -rf "$PROJECT_DIR/build" 2>/dev/null \
        || true
    [ ! -d "$PROJECT_DIR/build" ] && echo -e "  ${DIM}build/${NC}               ${GREEN}removed${NC}" && CLEANED=$((CLEANED + 1))
fi

# *.egg-info/ (setuptools package metadata)
for egg_dir in "$PROJECT_DIR"/*.egg-info "$PROJECT_DIR/src"/*.egg-info; do
    if [ -d "$egg_dir" ]; then
        rm -rf "$egg_dir" 2>/dev/null \
            || sudo rm -rf "$egg_dir" 2>/dev/null \
            || true
        dirname=$(basename "$egg_dir")
        [ ! -d "$egg_dir" ] && echo -e "  ${DIM}${dirname}/${NC}  ${GREEN}removed${NC}" && CLEANED=$((CLEANED + 1))
    fi
done

# __pycache__/ directories in source tree
PYCACHE_COUNT=0
while IFS= read -r -d '' pcdir; do
    rm -rf "$pcdir" 2>/dev/null || true
    PYCACHE_COUNT=$((PYCACHE_COUNT + 1))
done < <(find "$PROJECT_DIR/src/edgewalker" -name '__pycache__' -type d -not -path '*/.venv/*' -print0 2>/dev/null)
if [ "$PYCACHE_COUNT" -gt 0 ]; then
    echo -e "  ${DIM}__pycache__/${NC}          ${GREEN}removed${NC} ($PYCACHE_COUNT dirs)"
    CLEANED=$((CLEANED + 1))
fi

# *.pyc files (stray compiled bytecode)
PYC_COUNT=0
while IFS= read -r -d '' pycfile; do
    rm -f "$pycfile" 2>/dev/null || true
    PYC_COUNT=$((PYC_COUNT + 1))
done < <(find "$PROJECT_DIR/src/edgewalker" -name '*.pyc' -not -path '*/.venv/*' -print0 2>/dev/null)
if [ "$PYC_COUNT" -gt 0 ]; then
    echo -e "  ${DIM}*.pyc${NC}                ${GREEN}removed${NC} ($PYC_COUNT files)"
    CLEANED=$((CLEANED + 1))
fi

# dist/ directory (wheel / sdist output)
if [ -d "$PROJECT_DIR/dist" ]; then
    rm -rf "$PROJECT_DIR/dist" 2>/dev/null || true
    [ ! -d "$PROJECT_DIR/dist" ] && echo -e "  ${DIM}dist/${NC}               ${GREEN}removed${NC}" && CLEANED=$((CLEANED + 1))
fi

if [ "$CLEANED" -eq 0 ]; then
    echo -e "  No build artifacts found  ${DIM}skipped${NC}"
fi

# -- 4. Revert nmap capabilities (Linux only) --------------------------------

if [[ "$OSTYPE" == linux* ]]; then
    NMAP_PATH=$(which nmap)
    if [ -n "$NMAP_PATH" ]; then
        echo
        echo -ne "  Revert nmap capabilities? (requires sudo) [y/N] "
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            sudo setcap -r "$NMAP_PATH" 2>/dev/null && echo -e "  nmap capabilities   ${GREEN}reverted${NC}" \
                || echo -e "  nmap capabilities   ${DIM}failed or already clear${NC}"
        fi
    fi
fi

echo
echo -e "${GREEN}EdgeWalker uninstalled.${NC}"
echo
