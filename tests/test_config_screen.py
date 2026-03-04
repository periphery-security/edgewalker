# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from textual.widgets import Button, ContentSwitcher, Input, OptionList, Switch

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.config import ConfigScreen


@pytest.mark.asyncio
async def test_config_screen_mount():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            assert isinstance(app.screen, ConfigScreen)
            # Check if theme_selector is highlighted correctly
            theme_selector = screen.query_one("#theme_selector", OptionList)
            assert theme_selector.highlighted is not None


@pytest.mark.asyncio
async def test_config_screen_nav_selection():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            switcher = screen.query_one("#config-switcher", ContentSwitcher)
            assert switcher.current == "general"

            # Select "Appearance"
            nav = screen.query_one("#config-nav", OptionList)
            nav.highlighted = 1
            nav.post_message(OptionList.OptionSelected(nav, nav.get_option_at_index(1), 1))
            await pilot.pause()

            assert switcher.current == "appearance"


@pytest.mark.asyncio
async def test_config_screen_save_and_exit():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # Change a setting
            telemetry_switch = screen.query_one("#telemetry_enabled", Switch)
            telemetry_switch.value = not telemetry_switch.value

            api_timeout_input = screen.query_one("#api_timeout", Input)
            api_timeout_input.value = "42"

            with patch("edgewalker.tui.screens.config.update_setting") as mock_update:
                screen.action_save_and_exit()
                await pilot.pause()

                # Verify update_setting was called
                assert mock_update.called
                # Check if it was called with our new values
                # Note: update_setting might be called many times for all fields
                calls = [call.args for call in mock_update.call_args_list]
                assert ("telemetry_enabled", telemetry_switch.value) in calls
                assert ("api_timeout", "42") in calls

            # Verify screen was popped
            assert not isinstance(app.screen, ConfigScreen)


@pytest.mark.asyncio
async def test_config_screen_cancel():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # Press cancel button
            btn_cancel = screen.query_one("#btn-cancel", Button)
            btn_cancel.post_message(Button.Pressed(btn_cancel))
            await pilot.pause()

            # Verify screen was popped
            assert not isinstance(app.screen, ConfigScreen)


@pytest.mark.asyncio
async def test_config_screen_save_button():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(screen, "action_save_and_exit") as mock_save:
                btn_save = screen.query_one("#btn-save", Button)
                btn_save.post_message(Button.Pressed(btn_save))
                await pilot.pause()
                assert mock_save.called


@pytest.mark.asyncio
async def test_config_screen_theme_selection():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = ConfigScreen()
            await app.push_screen(screen)
            await pilot.pause()

            theme_selector = screen.query_one("#theme_selector", OptionList)
            theme_selector.highlighted = 0  # Should be periphery or default

            with patch("edgewalker.tui.screens.config.update_setting"):
                screen.action_save_and_exit()
                await pilot.pause()
                # If it was already periphery, app.theme might not change or it might be set to the same value
                # We just want to ensure it doesn't crash
