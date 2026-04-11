"""Extra tests for DashboardScreen to improve coverage."""

# Standard Library
import json
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

# Third Party
import pytest
from textual.widgets import RichLog

# First Party
from edgewalker.core.config import Settings, settings
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.dashboard import DashboardScreen


@pytest.mark.asyncio
async def test_dashboard_replay_log():
    """Test replaying the scan progress log on mount."""
    app = EdgeWalkerApp()
    app.scan_progress_log = [("phase", "Replayed Phase"), ("host_found", "1.2.3.4")]

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "Replayed Phase" in all_text
            assert "1.2.3.4" in all_text


@pytest.mark.asyncio
async def test_dashboard_auto_run_done():
    """Test _show_continue with label='Done' and auto_run=True."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen(auto_run=True)
            await app.push_screen(screen)
            await pilot.pause()

            screen._show_continue("Done")
            assert screen._auto_run is False


@pytest.mark.asyncio
async def test_dashboard_security_warnings_confirm(tmp_path):
    """Test security warnings confirmation flow."""
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
        patch.object(Settings, "get_security_warnings", return_value=["Warning 1"]),
        patch(
            "edgewalker.tui.screens.dashboard.get_active_overrides", return_value={"key": "source"}
        ),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            confirm_called = False

            def on_confirm():
                nonlocal confirm_called
                confirm_called = True

            # Trigger security check
            screen._check_security_warnings(on_confirm)
            await pilot.pause()

            # Should have pushed ConfirmModal
            # First Party
            from edgewalker.tui.modals.dialogs import ConfirmModal

            assert isinstance(app.screen, ConfirmModal)

            # Confirm
            await pilot.click("#confirm-yes")
            await pilot.pause()

            assert confirm_called is True


@pytest.mark.asyncio
async def test_dashboard_permission_error_fix(tmp_path):
    """Test handling permission error and choosing 'fix'."""
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
        patch("sys.platform", "linux"),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            @contextmanager
            def mock_suspend():
                yield

            with patch.object(app, "suspend", side_effect=mock_suspend):
                with patch(
                    "edgewalker.tui.screens.dashboard.fix_nmap_permissions", return_value=True
                ) as mock_fix:
                    with patch.object(screen, "_run_guided_port_scan") as mock_retry:
                        # Trigger permission error handler
                        screen._handle_permission_error("Permission Denied")
                        await pilot.pause()

                        # Should have pushed PermissionModal
                        # First Party
                        from edgewalker.tui.modals.dialogs import PermissionModal

                        assert isinstance(app.screen, PermissionModal)

                        # Select 'fix'
                        await pilot.click("#perm-fix")
                        await pilot.pause()

                        assert mock_fix.called
                        assert mock_retry.called


@pytest.mark.asyncio
async def test_dashboard_permission_error_unprivileged(tmp_path):
    """Test handling permission error and choosing 'unprivileged'."""
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

            with patch("edgewalker.tui.screens.dashboard.update_setting") as mock_update:
                with patch.object(screen, "_run_guided_port_scan") as mock_retry:
                    screen._handle_permission_error("Permission Denied")
                    await pilot.pause()

                    await pilot.click("#perm-unprivileged")
                    await pilot.pause()

                    mock_update.assert_called_with("unprivileged", True)
                    assert mock_retry.called


@pytest.mark.asyncio
async def test_dashboard_copy_report():
    """Test copying report to clipboard."""
    app = EdgeWalkerApp()
    app.copy_to_clipboard = MagicMock()

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            # No report yet
            screen.action_copy_report()
            assert not app.copy_to_clipboard.called

            # Set some report text
            screen._current_report_text = "Test Report Content"
            screen.action_copy_report()
            app.copy_to_clipboard.assert_called_with("Test Report Content")


@pytest.mark.asyncio
async def test_dashboard_topology_action(tmp_path):
    """Test action_topology with existing results."""
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(
        json.dumps({
            "hosts": [{"ip": "192.168.1.1", "state": "up", "tcp": []}],
            "summary": {"total_hosts": 1},
        })
    )

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            await screen.action_topology()
            await pilot.pause()

            assert screen.query_one("#topology-container").display is True
            assert screen.query_one("#topology-tree") is not None


@pytest.mark.asyncio
async def test_dashboard_on_tree_node_selected(tmp_path):
    """Test selecting a node in the topology tree."""
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

            # Mock event
            event = MagicMock()
            event.node.data = {"ip": "1.2.3.4", "type": "host"}

            with patch(
                "edgewalker.tui.screens.dashboard.build_device_report", return_value="Device Report"
            ) as mock_build:
                screen.on_tree_node_selected(event)
                assert mock_build.called
                assert screen._from_topology is True
                assert screen.query_one("#report-container").display is True


@pytest.mark.asyncio
async def test_dashboard_on_scan_error_retry():
    """Test _on_scan_error with retry logic."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen._auto_step = 2
            screen._on_scan_error("Error")
            assert screen._auto_step == 1

            screen._auto_step = 0
            screen._on_scan_error("Error")
            assert screen._auto_step == -1


@pytest.mark.asyncio
async def test_dashboard_view_raw():
    """Test action_view_raw."""
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(screen, "notify") as mock_notify:
                screen.action_view_raw()
                assert mock_notify.called


@pytest.mark.asyncio
async def test_dashboard_on_guided_sql_done(tmp_path):
    """Test _on_guided_sql_done."""
    app = EdgeWalkerApp()
    settings.output_dir = tmp_path
    (tmp_path / "port_scan.json").write_text(json.dumps({"hosts": [], "summary": {}}))

    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            results = {"summary": {"vulnerable_services": 1}}
            screen._on_guided_sql_done(results)

            log = screen.query_one("#wizard-log", RichLog)
            all_text = "\n".join(line.text for line in log.lines)
            assert "SQL SECURITY AUDIT" in all_text


@pytest.mark.asyncio
async def test_dashboard_handle_permission_error():
    """Test _handle_permission_error."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(app, "push_screen") as mock_push:
                screen._handle_permission_error("Permission denied")
                assert mock_push.called

                # Simulate "fix" choice
                callback = mock_push.call_args[0][1]
                with patch(
                    "edgewalker.tui.screens.dashboard.fix_nmap_permissions", return_value=True
                ):
                    with patch.object(screen, "_run_guided_port_scan") as mock_retry:
                        # Mock app.suspend to be a no-op context manager
                        # Standard Library
                        from contextlib import contextmanager

                        @contextmanager
                        def mock_suspend():
                            yield

                        with patch.object(app, "suspend", side_effect=mock_suspend):
                            callback("fix")
                            assert mock_retry.called

                # Simulate "unprivileged" choice
                with patch("edgewalker.tui.screens.dashboard.update_setting") as mock_update:
                    with patch.object(screen, "_run_guided_port_scan") as mock_retry:
                        callback("unprivileged")
                        assert mock_update.called
                        assert mock_retry.called


@pytest.mark.asyncio
async def test_dashboard_run_guided_scans():
    """Test _run_guided_*_scan methods."""
    app = EdgeWalkerApp()
    with patch("edgewalker.tui.app.check_nmap_permissions", return_value=True):
        async with app.run_test() as pilot:
            screen = DashboardScreen(show_report=False)
            await app.push_screen(screen)
            await pilot.pause()

            with patch.object(
                app.scanner, "perform_credential_scan", new_callable=AsyncMock
            ) as mock_cred:
                mock_cred.return_value = MagicMock(results=[], summary={})
                worker = screen._run_guided_cred_scan()
                await worker.wait()
                assert mock_cred.called

            with patch.object(app.scanner, "perform_cve_scan", new_callable=AsyncMock) as mock_cve:
                mock_cve.return_value = MagicMock(results=[], summary={})
                worker = screen._run_guided_cve_scan()
                await worker.wait()
                assert mock_cve.called

            with patch.object(app.scanner, "perform_sql_scan", new_callable=AsyncMock) as mock_sql:
                mock_sql.return_value = MagicMock(results=[], summary={})
                worker = screen._run_guided_sql_scan()
                await worker.wait()
                assert mock_sql.called

            with patch.object(app.scanner, "perform_web_scan", new_callable=AsyncMock) as mock_web:
                mock_web.return_value = MagicMock(results=[], summary={})
                # Mock file reading in _run_guided_web_scan
                with patch("builtins.open", mock_open(read_data='{"hosts": []}')):
                    worker = screen._run_guided_web_scan()
                    await worker.wait()
                    assert mock_web.called
