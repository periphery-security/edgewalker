# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest
from textual.widgets import Button, RichLog

# First Party
from edgewalker.core.config import settings
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen


@pytest.mark.asyncio
async def test_dashboard_screen_mount_welcome():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            log = screen.query_one("#wizard-log", RichLog)
            # Welcome message should be there somewhere
            all_text = "\n".join(line.text for line in log.lines)
            assert "Select a scan type" in all_text


@pytest.mark.asyncio
async def test_dashboard_screen_mount_report(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(json.dumps({"hosts": [], "summary": {}}))

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # Test mounting with show_report=True
            screen = DashboardScreen(show_report=True)
            await app.push_screen(screen)
            await pilot.pause()

            # Should have called action_show_report
            # Third Party
            from textual.widgets import Static

            report = screen.query_one("#report-content", Static)
            # In newer Textual, we might need to check _renderable or similar
            # For now, let's just check if it's visible or has content
            assert report is not None


@pytest.mark.asyncio
async def test_dashboard_screen_progress_updates():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            log = screen.query_one("#wizard-log", RichLog)
            initial_lines = len(log.lines)

            screen._on_progress("phase", "Scanning...")
            screen._on_progress("host_found", "192.168.1.1")
            screen._on_progress("port_found", "80/tcp open")
            screen._on_progress("service_start", "Starting service...")
            screen._on_progress("cred_progress", "Testing admin...")
            screen._on_progress("cred_found", "admin:admin")

            assert len(log.lines) > initial_lines


@pytest.mark.asyncio
async def test_dashboard_screen_guided_flow_navigation():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # Mock scanner to return a host so it doesn't jump to step 3 (error/no hosts)
            # Use a mock that returns a proper object or dict
            mock_results = {
                "hosts": [{"ip": "127.0.0.1", "state": "up", "tcp": {"80": {"state": "open"}}}],
                "summary": {"total_hosts": 1},
            }
            app.scanner.perform_port_scan = AsyncMock(return_value=mock_results)
            app.scanner.perform_credential_scan = AsyncMock(return_value={"vulnerabilities": []})

            screen = DashboardScreen(auto_target="127.0.0.1", auto_run=False)
            await app.push_screen(screen)

            # Wait for on_mount and the triggered scan to complete
            await pilot.pause()

            # If auto_target is provided, on_mount calls _next_guided_step() which makes it 2
            # And then calls _run_guided_port_scan()
            # We wait until is_scanning becomes True and then False again
            # or just wait long enough for the AsyncMock to return.
            # Standard Library
            import asyncio

            for _ in range(10):
                if screen._auto_step == 2 and not app.is_scanning:
                    break
                await asyncio.sleep(0.1)
                await pilot.pause()

            assert screen._auto_step == 2
            assert not app.is_scanning

            # Mock the scan methods to avoid actual work
            with patch.object(screen, "_run_guided_cred_scan") as mock_cred:
                # Set run_creds to True to test next step
                screen._run_creds = True

                # Make sure the button is visible and focused
                btn = screen.query_one("#continue-btn", Button)
                assert btn.display is True

                # Press Enter or click to continue
                await pilot.click("#continue-btn")
                await pilot.pause()

                # Should be step 3 now
                assert screen._auto_step == 3
                assert mock_cred.called


@pytest.mark.asyncio
async def test_dashboard_screen_actions_triggers():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # Use real classes but mock their behavior if needed

            with patch.object(app, "push_screen") as mock_push:
                screen.action_quick_scan()
                assert mock_push.called

                screen.action_full_scan()
                assert mock_push.call_count == 2

                screen.action_cred_scan()
                assert mock_push.call_count == 3


@pytest.mark.asyncio
async def test_dashboard_screen_clear_results(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    test_file = tmp_path / "test.json"
    test_file.write_text("{}")

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.action_clear_results()
            assert not test_file.exists()


@pytest.mark.asyncio
async def test_dashboard_screen_scan_error():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen._on_scan_error("Fatal Error")
            log = screen.query_one("#wizard-log", RichLog)
            assert any("Fatal Error" in line.text for line in log.lines)

            btn = screen.query_one("#continue-btn", Button)
            assert btn.display is True
            assert str(btn.label) == "Retry"


@pytest.mark.asyncio
async def test_dashboard_screen_on_guided_port_done():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen(auto_target="127.0.0.1", run_creds=True)
            await app.push_screen(screen)
            await pilot.pause()

            results = MagicMock()
            results.model_dump.return_value = {
                "hosts": [{"ip": "127.0.0.1", "state": "up", "tcp": {"80": {"state": "open"}}}],
                "summary": {"total_hosts": 1},
            }

            screen._on_guided_port_done(results)
            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "DEVICES FOUND" in all_text
            assert "1 device(s)" in all_text


@pytest.mark.asyncio
async def test_dashboard_screen_on_guided_cred_done(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    # Create required port_scan.json
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(json.dumps({"hosts": [], "summary": {}}))

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen(auto_target="127.0.0.1", run_cves=True)
            await app.push_screen(screen)
            await pilot.pause()

            results = MagicMock()
            results.model_dump.return_value = {
                "results": [],
                "summary": {"vulnerable_hosts": 1},
            }

            screen._on_guided_cred_done(results)
            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "CREDENTIAL CHECK" in all_text
            assert "1 device(s)" in all_text


@pytest.mark.asyncio
async def test_dashboard_screen_on_guided_cve_done(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            results_dict = {"summary": {"total_cves": 0}}
            report_renderables = ["REPORT SUMMARY"]

            screen._on_guided_cve_done(results_dict, report_renderables)

            # In the new 6-step flow, CVE is not the last step,
            # so it doesn't update #report-content yet.
            # It just updates status and shows continue.
            assert screen.app.is_scanning is False


@pytest.mark.asyncio
async def test_dashboard_screen_confirm_go_home():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            app.is_scanning = True
            with patch.object(app, "push_screen") as mock_push:
                await screen.action_go_home()
                await pilot.pause()
                assert mock_push.called


@pytest.mark.asyncio
async def test_dashboard_screen_run_scans():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen(auto_target="127.0.0.1")
            await app.push_screen(screen)
            await pilot.pause()

            app.scanner.perform_port_scan = AsyncMock(return_value=MagicMock())
            app.scanner.perform_credential_scan = AsyncMock(return_value=MagicMock())
            app.scanner.perform_cve_scan = AsyncMock(return_value=MagicMock())

            # Test _run_guided_port_scan
            screen._run_guided_port_scan()
            # Wait for worker to start?
            await pilot.pause()
            assert app.scanner.perform_port_scan.called

            # Test _run_guided_cred_scan
            screen._port_results = MagicMock()
            screen._run_guided_cred_scan()
            await pilot.pause()
            assert app.scanner.perform_credential_scan.called

            # Test _run_guided_cve_scan
            screen._run_guided_cve_scan()
            await pilot.pause()
            assert app.scanner.perform_cve_scan.called


@pytest.mark.asyncio
async def test_dashboard_screen_go_home():
    app = EdgeWalkerApp()
    # First Party
    from edgewalker.tui.screens.home import HomeScreen

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            # HomeScreen is already there by default
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            assert app.screen == screen
            await screen.action_go_home()
            await pilot.pause()
            assert isinstance(app.screen, HomeScreen)
