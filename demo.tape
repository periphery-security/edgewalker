# EdgeWalker Guided Assessment Demo
# This tape takes a user through the guided security assessment.

Output images/demo.gif

Set Shell "bash"
Set FontSize 22
Set Width 1920
Set Height 1080
Set Padding 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

# Start EdgeWalker
# Note: Run 'sudo -v' in your terminal before running 'vhs' to cache credentials.
Hide
Type "export EW_DEMO_MODE=1"
Enter
Show
Type "sudo -E uv run python -m edgewalker"
Enter

# Step 0: Handle Telemetry Opt-in
Wait+Screen /HELP SECURE IOT DEVICES/
Enter
Sleep 2s

# check that homepage is loaded
Wait+Screen /by Periphery/
Sleep 2s

# Step 1: Home Screen - Start Guided Assessment
Enter
Sleep 1.5s

# Step 2: Wizard Step 1 - Scan Depth
Tab
Sleep 500ms
Enter
Sleep 1s

# Step 3: Wizard Step 2 - Scan Target
Type "127.0.0.1"
Sleep 500ms
Enter
Sleep 2s

# Step 4: Wizard Step 3 - Additional Tests
Enter
Sleep 1s

# Step 5: Wizard Step 4 - Summary
Enter
Sleep 3s

# Now on Dashboard, scan is running.
Wait+Screen@60s /NETWORK SECURITY GRADE/
Sleep 3s

# Take a screenshot of the active scan
Screenshot "images/scan-report.png"

# Finish the demo
Sleep 2s
Type "q"
Sleep 500ms
