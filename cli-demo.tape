# EdgeWalker CLI demo — continuous change tracking (history & compare).
# Records against an isolated, pre-seeded history DB so there are reports to
# show (live demo mode does not persist). No sudo, no real scans.
#
#   vhs cli-demo.tape
#
# A one-line "configuration overrides detected" warning is expected because the
# demo relocates the data dir via EW_DATA_DIR; running against your real
# (chowned) ~/.edgewalker is warning-free.

Output images/cli-demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1600
Set Height 1000
Set Padding 12
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

# --- Seed an isolated history DB (hidden setup) ---
Hide
Type "export EW_DATA_DIR=$(mktemp -d) EW_CONFIG_DIR=$(mktemp -d) EW_CACHE_DIR=$(mktemp -d)"
Enter
Type "uv run python scripts/seed_demo_history.py >/dev/null 2>&1"
Enter
Sleep 2s
Type "clear"
Enter
Sleep 1s
Show

# --- List past assessment reports ---
Type "uv run edgewalker history --list"
Sleep 800ms
Enter
Wait+Screen /Reports/
Sleep 3s

Type "clear"
Enter

# --- Compare report #1 to report #3: what changed between them ---
Type "uv run edgewalker compare 1 3"
Sleep 800ms
Enter
Wait+Screen /Comparing/
Sleep 4s

Type "clear"
Enter

# --- Recent changes + score-trend sparkline ---
Type "uv run edgewalker history"
Sleep 800ms
Enter
Wait+Screen /Score trend/
Sleep 3s
