# Standard Library
from unittest.mock import patch

# Third Party
import pytest

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.home import HomeScreen


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_app_startup(mock_telemetry_enabled):
    """Test that the app starts and shows the home screen."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            assert isinstance(app.screen, HomeScreen)


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_home_screen_scan_button(mock_telemetry_enabled):
    """Test clicking scan button on home screen."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            await pilot.pause()
            # Click scan button
            await pilot.click("#btn-scan")
            await pilot.pause()
            # Should show GuidedAssessmentScreen
            # First Party
            from edgewalker.tui.screens.guided import GuidedAssessmentScreen

            assert isinstance(app.screen, GuidedAssessmentScreen)


@pytest.mark.asyncio
async def test_dashboard_screen_guided_flow():
    """Test DashboardScreen guided flow initialization."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            await pilot.pause()
            # Push DashboardScreen directly to test it
            screen = DashboardScreen(full_scan=False)
            await app.push_screen(screen)
            await pilot.pause()
            # DashboardScreen doesn't push TargetInputModal on mount anymore,
            # it's pushed by action_quick_scan or action_full_scan
            assert isinstance(app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_dashboard_screen_report_mode(tmp_path):
    """Test DashboardScreen in report mode."""
    app = EdgeWalkerApp()
    report_file = tmp_path / "port_scan.json"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(
        '{"hosts": [], "timestamp": "2026-02-25T10:00:00", "scan_type": "quick"}'
    )

    # First Party
    from edgewalker.core.config import settings

    old_dir = settings.output_dir
    settings.output_dir = tmp_path
    try:
        with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
            async with app.run_test() as pilot:
                await pilot.pause()
                await app.push_screen(DashboardScreen(show_report=True))
                await pilot.pause()
                assert isinstance(app.screen, DashboardScreen)
                # Verify RichLog exists
                assert app.screen.query_one("#wizard-log")
    finally:
        settings.output_dir = old_dir


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_dashboard_screen_actions(mock_telemetry_enabled):
    """Test DashboardScreen actions."""
    app = EdgeWalkerApp()
    # Mock permissions to allow scan actions
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = DashboardScreen(full_scan=False)
            await app.push_screen(screen)
            await pilot.pause()

            # Test navigation actions
            await pilot.press("3")  # Quick scan
            await pilot.pause()
            # First Party
            from edgewalker.tui.screens.guided import GuidedAssessmentScreen

            assert isinstance(app.screen, GuidedAssessmentScreen)
            await pilot.press("escape")
            await pilot.pause()

            await pilot.press("4")  # Full scan
            await pilot.pause()
            assert isinstance(app.screen, GuidedAssessmentScreen)
            await pilot.press("escape")
            await pilot.pause()


@pytest.mark.asyncio
async def test_telemetry_status_reactive():
    """Test that telemetry status updates reactively."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            await pilot.pause()
            # Push dashboard to see the status widget
            await app.push_screen(DashboardScreen())
            await pilot.pause()

            status_widget = app.screen.query_one("#telemetry-status")

            # Initial status
            assert app.telemetry_status == "disabled"

            assert "Disabled" in str(status_widget.render())

            # Update status
            app.telemetry_status = "sending"
            await pilot.pause()
            assert "Sending" in str(status_widget.render())

            app.telemetry_status = "success"
            await pilot.pause()
            assert "Sent" in str(status_widget.render())


@pytest.mark.asyncio
async def test_command_palette_filtering():
    """Test that the theme option is removed from the command palette."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            await pilot.pause()

            # Get system commands
            commands = list(app.get_system_commands(app.screen))

            # Verify "Theme" is NOT in the commands
            titles = [cmd.title for cmd in commands]
            assert "Theme" not in titles

            # Verify other system commands ARE present (e.g., "Quit")
            assert "Quit" in titles
