"""Tests for the boot splash and the About modal."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.modals.about import AboutModal
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.splash import SplashScreen


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_splash_auto_dismisses_to_dashboard(_seen):
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # Dashboard is the root surface (splash skipped under test mode).
            assert isinstance(app.screen, DashboardScreen)
            base = app.screen
            # Push a short splash; the timer alone should dissolve it back.
            await app.push_screen(SplashScreen(duration=0.1))
            await pilot.pause(0.4)
            assert app.screen is base


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_splash_skipped_by_keypress(_seen):
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            base = app.screen
            # Long duration so only the keypress can dismiss it.
            await app.push_screen(SplashScreen(duration=999))
            await pilot.pause()
            assert isinstance(app.screen, SplashScreen)
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen is base


@pytest.mark.asyncio
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
async def test_about_action_opens_modal(_seen):
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            app.action_about()
            await pilot.pause()
            assert isinstance(app.screen, AboutModal)

            # Content carries the brand/company info.
            # Third Party
            from textual.widgets import Static

            meta = app.screen.query_one("#about-meta", Static)
            assert "Periphery" in str(meta.render())

            # Closes cleanly.
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, AboutModal)
