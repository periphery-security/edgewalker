# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest
from textual.widgets import RichLog

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

            # Third Party
            from textual.widgets import Static

            screen._on_guided_web_done(results_dict, report_renderables)

            report = screen.query_one("#report-content", Static)
            # We can't easily get text from Static in tests without rendering
            # but we can check if it's visible and the container is displayed
            assert screen.query_one("#report-container").display is True
            assert screen.query_one("#wizard-log").display is False


@pytest.mark.asyncio
async def test_dashboard_screen_run_sql_web_scans():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            app.scanner.perform_sql_scan = AsyncMock(return_value=MagicMock())
            app.scanner.perform_web_scan = AsyncMock(return_value=MagicMock())

            # Test _run_guided_sql_scan
            screen._run_guided_sql_scan()
            await pilot.pause()
            assert app.scanner.perform_sql_scan.called

            # Test _run_guided_web_scan
            screen._run_guided_web_scan()
            await pilot.pause()
            assert app.scanner.perform_web_scan.called
