# EdgeWalker CLI demo — a full tour, end to end:
#   1. run a scan and watch the live log stream
#   2. the network security-grade overview
#   3. the per-device risk assessment
#   4. history & compare — what changed between two assessments
#
# Runs in demo mode (EW_DEMO_MODE=1): a simulated scan (no sudo, no nmap, no real
# network) that streams realistic progress and writes to an isolated demo.db. We
# pre-seed that DB so history/compare have past reports to show. Everything runs
# unprivileged against throwaway dirs.
#
#   vhs cli-demo.tape

Output images/cli-demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1600
Set Height 1000
Set Padding 12
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

# --- Hidden setup: isolated dirs, demo mode, pre-seeded history DB ---
# EW_TELEMETRY_ENABLED=false marks the telemetry choice as made (no opt-in
# prompt); EW_SUPPRESS_WARNINGS=true hides the env-override notice that the
# relocated dirs would otherwise print; --allow-override skips the scan's
# override confirmation.
Hide
Type "export EW_DATA_DIR=$(mktemp -d) EW_CONFIG_DIR=$(mktemp -d) EW_CACHE_DIR=$(mktemp -d)"
Enter
Type "export EW_DEMO_MODE=1 EW_TELEMETRY_ENABLED=false EW_SUPPRESS_WARNINGS=true"
Enter
Type "uv run python scripts/seed_demo_history.py >/dev/null 2>&1"
Enter
Sleep 2s
Type "clear"
Enter
Sleep 1s
Show

# === 1. Run a scan — watch the live log stream ======================
# Port discovery → credential testing → CVE lookup stream in phase by phase.
Type "uv run edgewalker scan --allow-override --unprivileged --target 192.168.1.0/24"
Sleep 800ms
Enter
Wait+Screen@60s /NETWORK SECURITY GRADE/
Sleep 3s

# === 2 & 3. The grade overview + per-device risk assessment =========
# `report` redraws the latest assessment: the NETWORK SECURITY GRADE panel
# (overview) and the DEVICE RISK ASSESSMENT table (the devices it found).
Type "clear"
Enter
Sleep 500ms
Type "uv run edgewalker report"
Sleep 800ms
Enter
Wait+Screen /DEVICE RISK ASSESSMENT/
Sleep 4s

# === 4. History & compare ===========================================
# List the past assessments, then diff two of them.
Type "clear"
Enter
Sleep 500ms
Type "uv run edgewalker history --list"
Sleep 800ms
Enter
Wait+Screen /Reports/
Sleep 3s

Type "clear"
Enter
Sleep 300ms
Type "uv run edgewalker compare 1 3"
Sleep 800ms
Enter
Wait+Screen /Comparing/
Sleep 4s
