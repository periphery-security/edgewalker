# Standard Library
from unittest.mock import patch

# Third Party
import pytest
from textual.style import Style

# First Party
from edgewalker.tui.app import EdgeWalkerApp, SettingsProvider, ThemeProvider
from edgewalker.tui.modals.dialogs import TelemetryModal
from edgewalker.tui.screens.config import ConfigScreen
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.home import HomeScreen


@pytest.mark.asyncio
async def test_app_init():
    with patch(
        "edgewalker.core.theme_manager.theme_manager.list_themes",
        return_value=[{"slug": "periphery", "name": "Periphery", "author": "EdgeWalker"}],
    ):
        app = EdgeWalkerApp()
        assert app.title == "EdgeWalker"
        assert app.theme == "periphery"


@pytest.mark.asyncio
async def test_app_mount_no_telemetry_prompt():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        with patch.object(app, "_check_previous_results") as mock_check:
            async with app.run_test() as pilot:
                await pilot.pause()
                assert isinstance(app.screen, HomeScreen)
                assert mock_check.called


@pytest.mark.asyncio
async def test_app_mount_with_telemetry_prompt():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=False,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            # TelemetryModal should be on top
            assert isinstance(app.screen, TelemetryModal)


@pytest.mark.asyncio
async def test_app_watch_theme():
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.update_setting") as mock_update:
        with patch("edgewalker.tui.app.load_active_theme"):
            async with app.run_test() as pilot:
                app.theme = "dracula"
                await pilot.pause()
                assert mock_update.called


@pytest.mark.asyncio
async def test_app_action_settings():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        app.action_settings()
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)


@pytest.mark.asyncio
async def test_app_action_quit_no_scan():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        with patch.object(app, "exit") as mock_exit:
            app.action_quit_app()
            assert mock_exit.called


@pytest.mark.asyncio
async def test_app_action_quit_with_scan():
    app = EdgeWalkerApp()
    app.is_scanning = True
    async with app.run_test() as pilot:
        app.action_quit_app()
        await pilot.pause()
        # Should push ConfirmModal
        # First Party
        from edgewalker.tui.modals.dialogs import ConfirmModal

        assert isinstance(app.screen, ConfirmModal)


@pytest.mark.asyncio
async def test_app_notify_progress():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        # Use DashboardScreen which has _on_progress
        screen = DashboardScreen()
        await app.push_screen(screen)

        with patch.object(screen, "_on_progress") as mock_on_progress:
            app.notify_progress("phase", "Test Phase")
            assert ("phase", "Test Phase") in app.scan_progress_log
            assert mock_on_progress.called


@pytest.mark.asyncio
async def test_settings_provider():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        provider = SettingsProvider(app.screen, Style())
        hits = [hit async for hit in provider.discover()]
        assert len(hits) == 1
        assert str(hits[0].text) == "Settings"

        hits = [hit async for hit in provider.search("Set")]
        assert len(hits) == 1
        assert "Settings" in str(hits[0].text)


@pytest.mark.asyncio
async def test_theme_provider():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        provider = ThemeProvider(app.screen, Style())
        hits = [hit async for hit in provider.discover()]
        assert len(hits) == 1
        assert str(hits[0].text) == "Theme"

        provider_only = ThemeProvider(app.screen, Style(), theme_only=True)
        hits = [hit async for hit in provider_only.discover()]
        assert len(hits) > 0


@pytest.mark.asyncio
async def test_app_telemetry_callback():
    app = EdgeWalkerApp()
    with (
        patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=False,
        ),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # TelemetryModal is pushed
            modal = app.screen
            # Simulate "Yes"
            with patch.object(app.telemetry, "set_telemetry_status") as mock_set:
                modal.dismiss(True)
                await pilot.pause()
                mock_set.assert_called_with(True)
                # Should push HomeScreen
                assert isinstance(app.screen, HomeScreen)


@pytest.mark.asyncio
async def test_app_action_theme_select():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        # Third Party
        from textual.command import CommandPalette

        with patch.object(app, "push_screen") as mock_push:
            app.action_theme_select()
            await pilot.pause()
            assert mock_push.called
            args, kwargs = mock_push.call_args
            assert isinstance(args[0], CommandPalette)


@pytest.mark.asyncio
async def test_app_action_set_theme():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        app.action_set_theme("dracula")
        await pilot.pause()
        assert app.theme == "dracula"
