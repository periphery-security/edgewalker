# Standard Library
import json
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from textual.widgets import Button, RichLog

# First Party
from edgewalker.core.config import settings
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen


@pytest.mark.asyncio
async def test_dashboard_screen_on_guided_sql_done(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path

    # Create required files for build_risk_report
    (tmp_path / "port_scan.json").write_text(json.dumps({"hosts": [], "summary": {}}))
    (tmp_path / "password_scan.json").write_text(json.dumps({"results": [], "summary": {}}))
    (tmp_path / "cve_scan.json").write_text(json.dumps({"results": [], "summary": {}}))
    (tmp_path / "web_scan.json").write_text(json.dumps({"results": [], "summary": {}}))

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            results = MagicMock()
            results.model_dump.return_value = {
                "results": [{"ip": "1.1.1.1", "service": "mysql", "status": "successful"}],
                "summary": {"vulnerable_services": 1},
            }

            screen._on_guided_sql_done(results)
            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "SQL SECURITY AUDIT" in all_text
            assert "1 SQL service(s)" in all_text


@pytest.mark.asyncio
async def test_dashboard_screen_on_guided_web_done(tmp_path):
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path

    # Create required files
    (tmp_path / "port_scan.json").write_text(json.dumps({"hosts": [], "summary": {}}))
    (tmp_path / "password_scan.json").write_text(json.dumps({"results": [], "summary": {}}))
    (tmp_path / "cve_scan.json").write_text(json.dumps({"results": [], "summary": {}}))
    (tmp_path / "sql_scan.json").write_text(json.dumps({"results": [], "summary": {}}))

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            results_dict = {
                "results": [
                    {"ip": "1.1.1.1", "protocol": "http", "port": 80, "headers": {"csp": False}}
                ],
                "summary": {"total_services": 1, "vulnerable_headers": 1},
            }
            report_renderables = ["REPORT SUMMARY"]

            screen._on_guided_web_done(results_dict, report_renderables)

            assert screen.query_one("#report-container").display is True
            assert screen.query_one("#wizard-log").display is False


@pytest.mark.asyncio
async def test_dashboard_screen_progress_events():
    """Test _on_progress events in DashboardScreen."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # Trigger various progress events
            screen._on_progress("phase", "Test Phase")
            screen._on_progress("host_found", "1.1.1.1")
            screen._on_progress("port_found", "80/tcp")
            screen._on_progress("service_start", "Scanning SSH")
            screen._on_progress("cred_progress", "Testing root")
            screen._on_progress("cred_found", "root:root")

            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "Test Phase" in all_text
            assert "Found host: 1.1.1.1" in all_text
            assert "Open port: 80/tcp" in all_text
            assert "Scanning SSH" in all_text
            assert "Testing root" in all_text
            assert "VULNERABLE: root:root" in all_text


@pytest.mark.asyncio
async def test_dashboard_screen_manual_continue():
    """Test manual progression with continue button."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen._auto_run = False
            screen._auto_step = 1
            screen._show_continue("Next")

            btn = screen.query_one("#continue-btn", Button)
            assert btn.display is True
            assert btn.label.plain == "Next"

            # Call handler directly to avoid pilot.click issues with mocks
            with patch.object(DashboardScreen, "_next_guided_step") as mock_next:
                screen.on_button_pressed(Button.Pressed(btn))
                assert mock_next.called


@pytest.mark.asyncio
async def test_dashboard_screen_on_key_enter():
    """Test manual progression with Enter key."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen._auto_step = 1
            app.is_scanning = False

            with patch.object(DashboardScreen, "_next_guided_step") as mock_next:
                # Call handler directly
                # Third Party
                from textual.events import Key

                screen.on_key(Key("enter", "enter"))
                assert mock_next.called


@pytest.mark.asyncio
async def test_dashboard_screen_clear_results(tmp_path):
    """Test action_clear_results."""
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")
    app.scan_progress_log = [("phase", "test")]

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.action_clear_results()
            assert not (tmp_path / "test.json").exists()
            assert app.scan_progress_log == []
