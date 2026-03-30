# Standard Library
from unittest.mock import patch

# Third Party
import pytest
from textual.widgets import Button

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.guided import GuidedAssessmentScreen
from edgewalker.tui.screens.home import HomeScreen


@pytest.mark.asyncio
async def test_home_screen_mount():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, HomeScreen)

            # Check if scan button is enabled
            btn_scan = screen.query_one("#btn-scan", Button)
            assert not btn_scan.disabled


@pytest.mark.asyncio
async def test_home_screen_no_permissions():
    app = EdgeWalkerApp()
    # Start with permissions to get to HomeScreen
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, HomeScreen)

            # Now simulate losing permissions
            with patch("edgewalker.core.config.settings.unprivileged", False):
                app.has_nmap_permissions = False
                screen._update_permissions()
                await pilot.pause()

                # Check if scan button is disabled
                btn_scan = screen.query_one("#btn-scan", Button)
                assert btn_scan.disabled


@pytest.mark.asyncio
async def test_home_screen_actions():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen

            # Test start_guided action
            await pilot.press("1")
            await pilot.pause()
            assert isinstance(app.screen, GuidedAssessmentScreen)
            app.pop_screen()
            await pilot.pause()

            # Test dashboard action
            await pilot.press("2")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)
            app.pop_screen()
            await pilot.pause()


@pytest.mark.asyncio
async def test_home_screen_buttons():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen

            # Test scan button
            await pilot.click("#btn-scan")
            await pilot.pause()
            assert isinstance(app.screen, GuidedAssessmentScreen)
            app.pop_screen()
            await pilot.pause()

            # Test dashboard button
            await pilot.click("#btn-dashboard")
            await pilot.pause()
            assert isinstance(app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_home_screen_watch_permissions():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen

            btn_scan = screen.query_one("#btn-scan", Button)
            assert not btn_scan.disabled

            # Change permissions
            with patch("edgewalker.core.config.settings.unprivileged", False):
                app.has_nmap_permissions = False
                screen._update_permissions()
                await pilot.pause()
                assert btn_scan.disabled


@pytest.mark.asyncio
async def test_home_screen_dashboard_with_results():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
        patch("edgewalker.tui.screens.home.has_port_scan", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen

            with patch.object(app, "push_screen") as mock_push:
                screen.action_dashboard()
                await pilot.pause()
                assert mock_push.called
                # Check if DashboardScreen was created with show_report=True
                args, kwargs = mock_push.call_args
                assert isinstance(args[0], DashboardScreen)
                assert args[0]._initial_report is True
