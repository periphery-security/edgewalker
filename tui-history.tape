# EdgeWalker TUI demo — the History view: score trend, change log, and the
# interactive report list (scroll + enter to pick two reports to compare).
#
# Runs unprivileged against a pre-seeded, isolated history DB — no sudo, no real
# scans (live demo mode does not persist history, so we seed it first).
#
#   vhs tui-history.tape
#
# A one-line "configuration overrides" notice is expected (the demo relocates the
# data dir via EW_DATA_DIR); running against a chowned ~/.edgewalker is clean.

Output images/tui-history.gif

Set Shell "bash"
Set FontSize 20
Set Width 1600
Set Height 1000
Set Padding 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

# --- Seed an isolated history DB (hidden setup) ---
Hide
Type "export EW_DATA_DIR=$(mktemp -d) EW_CONFIG_DIR=$(mktemp -d) EW_CACHE_DIR=$(mktemp -d)"
Enter
Type "export EW_DECLINE_TELEMETRY=1"
Enter
Type "uv run python scripts/seed_demo_history.py >/dev/null 2>&1"
Enter
Type "clear"
Enter
Show

# --- Launch the TUI (unprivileged: no nmap-permission modal) ---
Type "uv run edgewalker tui --unprivileged"
Enter

# Splash, then the dashboard overview.
Sleep 3s
Wait+Screen /by Periphery/
Sleep 1s
Enter
Wait+Screen /NETWORK SECURITY GRADE/
Sleep 2s

# --- Open the History view ---
Type "h"
Sleep 2s
Wait+Screen /Reports/
Sleep 2s

# Scroll the reports table and pick two reports to compare.
Down
Sleep 800ms
Enter
Sleep 1500ms
Down
Sleep 800ms
Enter
Wait+Screen /Comparing/
Sleep 4s

Screenshot "images/tui-history.png"

# Quit.
Type "q"
Sleep 500ms
