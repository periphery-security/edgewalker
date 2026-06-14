# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from textual.widgets import Button, Checkbox, Input, RadioButton

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.guided import GuidedAssessmentScreen


@pytest.mark.asyncio
async def test_guided_screen_start_returns_config():
    """Configuring and starting returns the collected config to the caller."""
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.query_one("#wizard-target-input", Input).value = "192.168.1.0/24"
            screen.query_one("#chk-sql", Checkbox).value = False
            await pilot.pause()

            with patch.object(screen, "dismiss") as mock_dismiss:
                btn = screen.query_one("#btn-start", Button)
                btn.post_message(Button.Pressed(btn))
                await pilot.pause()
                assert mock_dismiss.called
                config = mock_dismiss.call_args[0][0]
                assert config["target"] == "192.168.1.0/24"
                assert config["run_sql"] is False
                assert config["full_scan"] is False


@pytest.mark.asyncio
async def test_guided_screen_full_scan_preselected():
    """Launching for a full scan pre-selects the full-scan radio."""
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen(full_scan=True)
            await app.push_screen(screen)
            await pilot.pause()

            assert screen.query_one("#radio-full", RadioButton).value is True
            assert screen._collect()["full_scan"] is True


@pytest.mark.asyncio
async def test_guided_screen_cancel_returns_none():
    """Cancel/escape dismisses with no config (no scan runs)."""
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(screen, "dismiss") as mock_dismiss:
                screen.action_cancel()
                assert mock_dismiss.called
                assert mock_dismiss.call_args[0][0] is None


@pytest.mark.asyncio
async def test_guided_screen_input_submit_starts_scan():
    """Pressing Enter in the target field starts the scan."""
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            target_input = screen.query_one("#wizard-target-input", Input)
            target_input.value = "10.0.0.1"
            with patch.object(screen, "dismiss") as mock_dismiss:
                target_input.post_message(Input.Submitted(target_input, "10.0.0.1"))
                await pilot.pause()
                assert mock_dismiss.called
                assert mock_dismiss.call_args[0][0]["target"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_guided_screen_quit():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(app, "action_quit_app") as mock_quit:
                screen.action_quit_app()
                assert mock_quit.called
