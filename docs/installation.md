# Installation

## Prerequisites

- **Python 3.13+**
- **nmap** — EdgeWalker requires `nmap` for port scanning (the install script installs this automatically)

## Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/periphery-security/edgewalker/main/scripts/install.sh | bash
```

## Install from Source

```bash
git clone https://github.com/periphery-security/edgewalker.git
cd edgewalker
bash scripts/install.sh
```

The install script:

1. Checks for Python 3.13+
2. Installs `nmap` if missing (supports Homebrew, apt, dnf, pacman)
3. Installs `pipx` if missing
4. Installs EdgeWalker as an isolated CLI command via `pipx`

## Manual Install (without the script)

If you prefer to manage dependencies yourself:

```bash
git clone https://github.com/periphery-security/edgewalker.git
cd edgewalker
pip install .
```

Or run directly without installing:

```bash
cd edgewalker
pip install -r requirements.txt
python -m edgewalker          # TUI mode (might require sudo on macOS)
python -m edgewalker scan     # CLI mode (might require sudo on macOS)
```

## Uninstall

```bash
bash scripts/uninstall.sh
```

This removes:

- The `edgewalker` package (via pipx or pip)
- Configuration and scan results (platform-specific, e.g., `~/Library/Application Support/edgewalker/` on macOS)
- Cached vendor data (platform-specific, e.g., `~/Library/Caches/edgewalker/` on macOS)
- Build artifacts (`build/`, `*.egg-info/`, `__pycache__/`, `dist/`)

To uninstall without the script:

```bash
pipx uninstall edgewalker
# On macOS:
rm -rf "~/Library/Application Support/edgewalker" "~/Library/Caches/edgewalker"
# On Linux:
rm -rf ~/.config/edgewalker ~/.cache/edgewalker
```

## Platform Notes

- **macOS**: Requires Homebrew for automatic nmap installation. Port scanning requires `sudo`.
- **Linux**: Supports apt (Debian/Ubuntu), dnf (Fedora/RHEL), and pacman (Arch). The installer automatically configures `nmap` capabilities, removing the need for `sudo`.
- **Windows**: EdgeWalker currently lacks support for Windows (nmap and raw socket access behave differently).
