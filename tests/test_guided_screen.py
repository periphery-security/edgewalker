# Standard Library
import io
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from rich.console import Console
from textual.widgets import Button, Checkbox, Input, RadioButton

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen
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
async def test_guided_screen_thorough_creds_gated_on_creds():
    """Thorough-creds is disabled and forced off when default-passwords is off."""
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = GuidedAssessmentScreen()
            await app.push_screen(screen)
            await pilot.pause()

            creds = screen.query_one("#chk-creds", Checkbox)
            thorough = screen.query_one("#chk-full-creds", Checkbox)

            # Enabled while credential testing is on (the default).
            assert thorough.disabled is False

            # Turn off default passwords → thorough is disabled and cleared.
            thorough.value = True
            creds.value = False
            await pilot.pause()
            assert thorough.disabled is True
            assert thorough.value is False

            # And it never leaks into the collected config.
            assert screen._collect()["full_creds"] is False


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
async def test_guided_screen_is_modal_over_dashboard():
    """The config is a translucent modal — the dashboard shows through behind."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test(size=(120, 35)) as pilot:
            await app.push_screen(DashboardScreen())
            await pilot.pause()
            await app.push_screen(GuidedAssessmentScreen())
            await pilot.pause()

            screen = app.screen
            # Translucent screen background (dimmed dashboard, not opaque).
            assert screen.styles.background.a < 1.0
            # The dashboard is a background screen below the modal.
            assert any(isinstance(s, DashboardScreen) for s in app._background_screens)

            # And its sidebar content actually composites through the veil.
            console = Console(width=120, height=35, file=io.StringIO(), record=True)
            console.print(
                app.screen._compositor.render_update(
                    full=True, screen_stack=app._background_screens, simplify=True
                )
            )
            composite = console.export_text()
            assert "Network" in composite  # a dashboard sidebar label, shown behind


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
