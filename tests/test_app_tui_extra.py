"""Extra tests for EdgeWalkerApp to improve coverage."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.tui.app import EdgeWalkerApp, SettingsProvider, ThemeProvider, VersionProvider


@pytest.mark.asyncio
async def test_version_provider_search():
    """Test VersionProvider search."""
    app = EdgeWalkerApp()
    provider = VersionProvider(app)

    # Match
    hits = [hit async for hit in provider.search("Vers")]
    assert len(hits) == 1
    # hit.text might be a Rich Text object or a string
    text = hits[0].text
    assert "Version" in (text.plain if hasattr(text, "plain") else str(text))

    # No match
    hits = [hit async for hit in provider.search("NoMatch")]
    assert len(hits) == 0


@pytest.mark.asyncio
async def test_settings_provider_search():
    """Test SettingsProvider search."""
    app = EdgeWalkerApp()
    provider = SettingsProvider(app)

    # Match
    hits = [hit async for hit in provider.search("Sett")]
    assert len(hits) == 1
    text = hits[0].text
    assert "Settings" in (text.plain if hasattr(text, "plain") else str(text))

    # No match
    hits = [hit async for hit in provider.search("NoMatch")]
    assert len(hits) == 0


@pytest.mark.asyncio
async def test_theme_provider_search():
    """Test ThemeProvider search."""
    app = EdgeWalkerApp()
    # Third Party
    from textual.style import Style

    with (
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # theme_only = False
            provider = ThemeProvider(app.screen, Style(), theme_only=False)
            hits = [hit async for hit in provider.search("Theme")]
            assert len(hits) == 1
            text = hits[0].text
            assert "Theme" in (text.plain if hasattr(text, "plain") else str(text))

            # theme_only = True
            provider = ThemeProvider(app.screen, Style(), theme_only=True)
            with patch(
                "edgewalker.core.theme_manager.theme_manager.list_themes",
                return_value=[{"slug": "periphery", "name": "Periphery", "author": "Auth"}],
            ):
                hits = [hit async for hit in provider.search("Periphery")]
                assert len(hits) == 1
                assert "Periphery" in (
                    hits[0].text.plain if hasattr(hits[0].text, "plain") else str(hits[0].text)
                )


@pytest.mark.asyncio
async def test_app_config_overrides():
    """Test _check_config_overrides."""
    app = EdgeWalkerApp()
    with patch("edgewalker.core.config.get_active_overrides", return_value={"key": "env"}):
        with patch.object(app, "notify") as mock_notify:
            assert app._check_config_overrides() is True
            assert mock_notify.called


@pytest.mark.asyncio
async def test_app_quit_scanning():
    """Test action_quit_app when scanning."""
    app = EdgeWalkerApp()
    app.is_scanning = True

    with (
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # Trigger quit
            app.action_quit_app()
            await pilot.pause()

            # Should show ConfirmModal
            # First Party
            from edgewalker.tui.modals.dialogs import ConfirmModal

            assert isinstance(app.screen, ConfirmModal)

            # Confirm quit
            await pilot.press("enter")
            await pilot.pause()
            # App should exit (in test it might just set a flag)


@pytest.mark.asyncio
async def test_app_update_telemetry_status_thread():
    """Test _update_telemetry_status from a different thread."""
    app = EdgeWalkerApp()

    with patch.object(app, "call_from_thread") as mock_call:
        # Mock current thread to NOT be main thread
        with patch("threading.current_thread", return_value=MagicMock()):
            app._update_telemetry_status("active")
            assert mock_call.called


@pytest.mark.asyncio
async def test_app_watch_theme_error():
    """Test watch_theme with an error."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.update_setting", side_effect=Exception("Save failed")):
        with patch.object(app, "notify") as mock_notify:
            app.watch_theme("new-theme")
            mock_notify.assert_called_with(
                "Failed to save theme setting: Save failed", severity="error"
            )


@pytest.mark.asyncio
async def test_app_action_set_theme_none():
    """Test action_set_theme with None."""
    app = EdgeWalkerApp()
    old_theme = app.theme
    app.action_set_theme(None)
    assert app.theme == old_theme


@pytest.mark.asyncio
async def test_app_action_settings():
    """Test action_settings."""
    app = EdgeWalkerApp()
    with (
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            app.action_settings()
            await pilot.pause()
            # First Party
            from edgewalker.tui.screens.config import ConfigScreen

            assert isinstance(app.screen, ConfigScreen)
