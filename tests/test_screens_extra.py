# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen
from edgewalker.tui.screens.guided import GuidedAssessmentScreen
from edgewalker.tui.screens.home import HomeScreen


@pytest.mark.asyncio
async def test_home_screen_actions(tmp_path):
    app = EdgeWalkerApp()
    # Mock Header to avoid HeaderTitle issues and permissions to allow scan
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, HomeScreen)

            # Test action_start_guided
            app.screen.action_start_guided()
            await pilot.pause()
            assert isinstance(app.screen, GuidedAssessmentScreen)


@pytest.mark.asyncio
async def test_dashboard_screen_on_scan_error():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = DashboardScreen(full_scan=False)
            await app.push_screen(screen)
            await pilot.pause()

            screen._on_scan_error("Test Error")
            # In my new code, _auto_step becomes -1 if not in guided mode
            assert screen._auto_step == -1


@pytest.mark.asyncio
async def test_dashboard_screen_continue_actions():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            # Initialize with run_creds=True so it calls _run_guided_cred_scan
            screen = DashboardScreen(full_scan=False, run_creds=True)
            await app.push_screen(screen)
            await pilot.pause()

            # Set to 2 so it increments to 3 and calls _run_guided_cred_scan
            screen._auto_step = 2
            with patch.object(screen, "_run_guided_cred_scan") as mock_run:
                screen._on_continue_pressed()
                assert mock_run.called


@pytest.mark.asyncio
async def test_dashboard_screen_progress_callback():
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            screen = DashboardScreen(full_scan=False)
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(screen, "_write_phase") as mock_write:
                cb = screen._make_progress_callback()
                cb("phase", "Test")
                assert mock_write.called


@pytest.mark.asyncio
async def test_dashboard_screen_on_scan_error_report_mode(tmp_path):
    app = EdgeWalkerApp()
    with patch("textual.widgets.Header", return_value=MagicMock()):
        async with app.run_test() as pilot:
            # First Party
            from edgewalker.core.config import settings

            old_dir = settings.output_dir
            settings.output_dir = tmp_path
            try:
                port_file = tmp_path / "port_scan.json"
                port_file.write_text('{"hosts": [], "summary": {}}')

                screen = DashboardScreen(show_report=True)
                await app.push_screen(screen)
                await pilot.pause()

                screen._on_scan_error("Error")
                assert screen._auto_step == -1
            finally:
                settings.output_dir = old_dir
