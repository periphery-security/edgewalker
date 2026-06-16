# EdgeWalker TUI demo — a full guided tour:
#   1. run a scan and watch the live log
#   2. the at-a-glance overview
#   3. the device table → drill into a device
#   4. the History view → pick two reports and read the comparison
#
# Runs in demo mode (EW_DEMO_MODE=1): a simulated scan (no sudo, no nmap, no real
# network) against a pre-seeded, isolated history DB so the History view has
# reports to compare. Modals are skipped where possible: EW_TELEMETRY_ENABLED=false
# pre-decides the telemetry opt-in and --unprivileged skips the nmap-permission
# prompt. The brief "security & configuration check" before the scan is EdgeWalker
# flagging the demo's env-var overrides; we confirm it (Tab → Enter).
#
#   vhs demo.tape

Output images/demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1920
Set Height 1200
Set Padding 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

# --- Hidden setup: isolated dirs, demo mode, seeded history DB ---
Hide
Type "export EW_DATA_DIR=$(mktemp -d) EW_CONFIG_DIR=$(mktemp -d) EW_CACHE_DIR=$(mktemp -d)"
Enter
Type "export EW_DEMO_MODE=1 EW_TELEMETRY_ENABLED=false"
Enter
Type "uv run python scripts/seed_demo_history.py >/dev/null 2>&1"
Enter
Sleep 2s
Type "clear"
Enter
Sleep 1s
Show

# --- Launch the TUI (demo mode, unprivileged → no nmap/telemetry modals) ---
Type "uv run edgewalker tui --unprivileged"
Enter
# Cold start + the branded splash dissolves into the dashboard.
Sleep 6s

# === 1. Run a scan and watch the live log ===========================
Type "s"
Sleep 1500ms
Enter
Sleep 1s
# Confirm the "security & configuration check" (demo env overrides).
Tab
Sleep 500ms
Enter
# The live-log view streams the port → credential → CVE → SQL → web phases.
Sleep 6s
Wait+Screen@60s /Assessment complete/

# === 2. The at-a-glance overview ====================================
# The scan lands here automatically: SECURITY GRADE, network, findings, devices.
Sleep 4s
Screenshot "images/scan-report.png"

# === 3. The device table → drill into a device =====================
Type "d"
Sleep 1500ms
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 600ms
Enter
Sleep 3s
Screenshot "images/device-report.png"
Sleep 1s

# === 4. The History view → pick two reports, read the comparison ====
Type "h"
Sleep 1s
Wait+Screen /Score trend/
Sleep 2s
# Scroll the reports table and pick two to compare; the diff renders below.
Enter
Sleep 1200ms
Down
Sleep 1s
Enter
Wait+Screen /Comparing/
Sleep 4s

# Finish.
Type "q"
Sleep 500ms
