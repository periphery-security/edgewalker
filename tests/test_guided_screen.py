# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from textual.widgets import Button, Input, RadioSet, Static

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.guided import GuidedAssessmentScreen


@pytest.mark.asyncio
async def test_guided_screen_flow():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            assert screen.step == 1
            title = screen.query_one("#wizard-title", Static)
            assert "STEP 1" in str(title.content)

            # Step 1 -> 2
            btn_next = screen.query_one("#btn-next", Button)
            btn_next.post_message(Button.Pressed(btn_next))
            await pilot.pause()
            assert screen.step == 2
            assert "STEP 2" in str(title.content)

            # Step 2 -> 3
            target_input = screen.query_one("#wizard-target-input", Input)
            target_input.value = "192.168.1.0/24"
            btn_next.post_message(Button.Pressed(btn_next))
            await pilot.pause()
            assert screen.step == 3
            assert "STEP 3" in str(title.content)
            assert screen.config["target"] == "192.168.1.0/24"

            # Step 3 -> 4
            btn_next.post_message(Button.Pressed(btn_next))
            await pilot.pause()
            assert screen.step == 4
            assert "READY TO RUN" in str(title.content)

            # Step 4 -> Dashboard
            with patch.object(app, "push_screen") as mock_push:
                btn_next.post_message(Button.Pressed(btn_next))
                await pilot.pause()
                assert mock_push.called
                # Check if DashboardScreen was pushed
                args, kwargs = mock_push.call_args
                assert isinstance(args[0], DashboardScreen)


@pytest.mark.asyncio
async def test_guided_screen_back_button():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.step = 2
            screen._update_step()
            await pilot.pause()

            btn_back = screen.query_one("#btn-back", Button)
            btn_back.post_message(Button.Pressed(btn_back))
            await pilot.pause()
            assert screen.step == 1

            # Back on step 1 should pop screen
            btn_back.post_message(Button.Pressed(btn_back))
            await pilot.pause()
            assert app.screen != screen


@pytest.mark.asyncio
async def test_guided_screen_radio_changed():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            radio_set = screen.query_one("#wizard-depth-radio", RadioSet)
            radio_full = screen.query_one("#radio-full")
            radio_set.post_message(RadioSet.Changed(radio_set, radio_full))
            await pilot.pause()
            assert screen.config["full_scan"] is True


@pytest.mark.asyncio
async def test_guided_screen_input_submitted():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.step = 2
            screen._update_step()
            await pilot.pause()

            target_input = screen.query_one("#wizard-target-input", Input)
            target_input.post_message(Input.Submitted(target_input, "10.0.0.1"))
            await pilot.pause()
            assert screen.step == 3
            assert screen.config["target"] == "10.0.0.1"
