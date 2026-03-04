# Standard Library
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

# Third Party
import pytest

# First Party
from edgewalker import cli


@pytest.fixture(autouse=True)
def mock_settings_dir(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    old_dir = settings.output_dir
    settings.output_dir = tmp_path
    yield settings
    settings.output_dir = old_dir


@patch("edgewalker.core.scanner_service.port_scan.quick_scan", new_callable=AsyncMock)
@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch("edgewalker.core.scanner_service.save_results")
@patch("edgewalker.core.scanner_service.submit_scan_data")
def test_run_port_scan_fail(mock_submit, mock_save, mock_input, mock_quick):
    # First Party
    from edgewalker.modules.port_scan.models import PortScanModel

    mock_quick.return_value = PortScanModel(success=False, error="nmap error", hosts=[])
    res = cli.run_port_scan()
    assert res is None


@patch("edgewalker.cli.controller.settings")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data='{"id": "test", "device_id": "test", "version": "0.1.0", "module": "port_scan", "module_version": "0.1.0", "hosts": [{"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00"}]}',
)
@patch("edgewalker.utils.get_input", side_effect=["10"])
@patch("edgewalker.core.scanner_service.password_scan.scan", new_callable=AsyncMock)
@patch("edgewalker.core.scanner_service.save_results")
@patch("edgewalker.core.scanner_service.submit_scan_data")
def test_run_credential_scan_from_file(
    mock_submit, mock_save, mock_scan, mock_input, mock_file, mock_settings
):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel

    mock_port_file = MagicMock()
    mock_port_file.exists.return_value = True
    mock_settings.output_dir.__truediv__.return_value = mock_port_file
    mock_scan.return_value = PasswordScanModel(
        hosts=[],
        results=[],
        summary={
            "vulnerable_hosts": 0,
            "total_hosts": 0,
            "services_tested": 0,
            "credentials_found": 0,
        },
    )

    cli.run_credential_scan()
    assert mock_scan.called


@patch("edgewalker.cli.controller.settings")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data='{"id": "test", "device_id": "test", "version": "0.1.0", "module": "port_scan", "module_version": "0.1.0", "hosts": [{"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00"}]}',
)
@patch("edgewalker.utils.get_input", side_effect=["1.1.1.1", "all"])
@patch("edgewalker.core.scanner_service.password_scan.scan", new_callable=AsyncMock)
@patch("edgewalker.core.scanner_service.save_results")
def test_run_credential_scan_manual_target(
    mock_save, mock_scan, mock_input, mock_file, mock_settings
):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel

    mock_port_file = MagicMock()
    mock_port_file.exists.return_value = True
    mock_settings.output_dir.__truediv__.return_value = mock_port_file

    mock_scan.return_value = PasswordScanModel(
        hosts=[],
        results=[],
        summary={
            "vulnerable_hosts": 0,
            "total_hosts": 0,
            "services_tested": 0,
            "credentials_found": 0,
        },
    )
    cli.run_credential_scan()
    assert mock_scan.called


@patch("edgewalker.cli.controller.settings")
@patch("builtins.open", new_callable=mock_open, read_data='{"hosts": []}')
def test_run_cve_scan_no_file(mock_file, mock_settings):
    mock_port_file = MagicMock()
    mock_port_file.exists.return_value = False
    mock_settings.output_dir.__truediv__.return_value = mock_port_file
    assert cli.run_cve_scan() is None


@patch("edgewalker.cli.controller.settings")
@patch("builtins.open", new_callable=mock_open, read_data='{"hosts": []}')
def test_run_cve_scan_no_hosts(mock_file, mock_settings):
    mock_port_file = MagicMock()
    mock_port_file.exists.return_value = True
    mock_settings.output_dir.__truediv__.return_value = mock_port_file
    assert cli.run_cve_scan() is None


@patch("edgewalker.core.config.settings")
@patch("builtins.open", new_callable=mock_open, read_data='{"hosts": []}')
def test_view_device_risk_no_file(mock_file, mock_dir):
    mock_dir.output_dir.__truediv__.return_value.exists.return_value = False
    cli.ScanController().view_device_risk()  # Should return early


@patch("edgewalker.core.config.settings")
def test_view_results_no_dir(mock_dir):
    mock_dir.output_dir.exists.return_value = False
    cli.ResultManager().view_results()


@patch("edgewalker.core.config.settings")
def test_view_results_no_files(mock_dir):
    mock_dir.output_dir.exists.return_value = True
    mock_dir.output_dir.glob.return_value = []
    cli.ResultManager().view_results()


@patch("edgewalker.core.config.settings")
def test_clear_results_no_dir(mock_dir):
    mock_dir.output_dir.exists.return_value = False
    cli.ResultManager().clear_results()


@patch("edgewalker.core.config.settings")
def test_clear_results_no_files(mock_dir):
    mock_dir.output_dir.exists.return_value = True
    mock_dir.output_dir.glob.return_value = []
    cli.ResultManager().clear_results()


@patch("edgewalker.utils.get_input", return_value="0")
def test_show_mode_selection_exit(mock_input):
    # First Party
    from edgewalker.cli.menu import InteractiveMenu

    controller = MagicMock()
    results = MagicMock()
    guided = MagicMock()
    menu = InteractiveMenu(controller, results, guided)
    assert menu._show_mode_selection() == "exit"


@patch("edgewalker.cli.guided.GuidedScanner._show_scan_type_selection", return_value=False)
@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch("edgewalker.cli.controller.ScanController.run_port_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.utils.press_enter")
def test_automatic_mode_full_flow(
    mock_press, mock_risk, mock_cve, mock_pwd, mock_port, mock_input, mock_type
):
    # First Party
    from edgewalker.modules.port_scan.models import PortScanModel

    mock_port.return_value = PortScanModel(
        hosts=[{"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00"}]
    )
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    cli.automatic_mode()
    assert mock_risk.called


@patch("edgewalker.utils.get_input", side_effect=["1", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=False)
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_no_port_scan(
    mock_build, mock_press, mock_has_port, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()
    # Should show warning and not call view_device_risk


@patch("edgewalker.utils.get_input", side_effect=["3", "n", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_full_scan_cancel(
    mock_press, mock_build, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()


@patch("edgewalker.utils.get_input", side_effect=["4", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=False)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_creds_no_port(
    mock_press, mock_build, mock_has_port, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()


@patch("edgewalker.utils.get_input", side_effect=["5", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=False)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_cve_no_port(
    mock_press, mock_build, mock_has_port, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()


@patch("edgewalker.utils.get_input", side_effect=["99", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_invalid(
    mock_press, mock_build, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()


@patch("edgewalker.utils.get_input", side_effect=[""])
@patch("edgewalker.core.config.settings")
def test_view_results_select_invalid(mock_dir, mock_input):
    mock_dir.output_dir.exists.return_value = True
    mock_file = MagicMock()
    mock_file.name = "test.json"
    mock_file.stat.return_value.st_size = 1024
    mock_file.stat.return_value.st_mtime = 1600000000
    mock_dir.output_dir.glob.return_value = [mock_file]
    cli.ResultManager().view_results()


@patch("edgewalker.utils.get_input", side_effect=["n"])
@patch("edgewalker.core.config.settings")
def test_clear_results_cancel(mock_dir, mock_input):
    mock_dir.output_dir.exists.return_value = True
    mock_file = MagicMock()
    mock_file.name = "test.json"
    mock_dir.output_dir.glob.return_value = [mock_file]
    cli.ResultManager().clear_results()


@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", side_effect=["n"])
def test_prompt_next_scan_no(mock_input, mock_status):
    mock_status.return_value = {
        "port_scan": True,
        "port_scan_type": None,
        "password_scan": False,
        "cve_scan": False,
        "devices_found": 0,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    controller = MagicMock()
    guided = cli.GuidedScanner(controller)
    cli.prompt_next_scan()


@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", side_effect=["n"])
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
def test_prompt_next_scan_creds_no(mock_run, mock_input, mock_status):
    mock_status.return_value = {"port_scan": True, "password_scan": False, "cve_scan": False}
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    cli.prompt_next_scan()
    assert not mock_run.called


@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", side_effect=["n"])
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
def test_prompt_next_scan_cve_no(mock_run, mock_input, mock_status):
    mock_status.return_value = {"port_scan": True, "password_scan": True, "cve_scan": False}
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    cli.prompt_next_scan()
    assert not mock_run.called


@patch("edgewalker.core.config.settings")
@patch("edgewalker.utils.get_input", side_effect=["n"])
@patch("edgewalker.utils.press_enter")
def test_check_previous_results_no(mock_press, mock_input, mock_dir):
    with patch("edgewalker.utils.has_any_results", return_value=True):
        mock_dir.output_dir.glob.return_value = [MagicMock()]
        cli.ResultManager().check_previous_results()


@patch("edgewalker.cli.menu.settings")
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.utils.get_input")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
def test_interactive_mode_report_exists(
    mock_telemetry_enabled, mock_input, mock_press, mock_risk, mock_dir
):
    with patch(
        "edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["report", "exit"]
    ):
        with patch("edgewalker.utils.has_any_results", return_value=False):
            mock_report = MagicMock()
            mock_report.exists.return_value = True
            mock_dir.output_dir.__truediv__.return_value = mock_report
            cli.interactive_mode()
            assert mock_risk.called


@patch("edgewalker.cli.menu.settings")
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.utils.get_input")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("builtins.open", new_callable=mock_open, read_data='{"hosts": []}')
def test_interactive_mode_report_not_exists(
    mock_file, mock_telemetry_enabled, mock_input, mock_press, mock_dir
):
    with patch(
        "edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["report", "exit"]
    ):
        with patch("edgewalker.utils.has_any_results", return_value=False):
            mock_report = MagicMock()
            mock_report.exists.return_value = False
            mock_dir.output_dir.__truediv__.return_value = mock_report
            cli.interactive_mode()


@patch("edgewalker.cli.guided.GuidedScanner.automatic_mode", new_callable=AsyncMock)
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.get_input")
def test_interactive_mode_auto(mock_input, mock_telemetry_enabled, mock_auto):
    with patch(
        "edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["auto", "exit"]
    ):
        with patch("edgewalker.utils.has_any_results", return_value=False):
            with patch("edgewalker.utils.press_enter"):
                cli.interactive_mode()
                assert mock_auto.called


@patch("edgewalker.utils.get_input", side_effect=["", "invalid", "0"])
@patch("edgewalker.core.config.settings")
def test_view_results_select_errors(mock_dir, mock_input):
    mock_dir.output_dir.exists.return_value = True
    mock_file = MagicMock()
    mock_file.name = "test.json"
    mock_file.stat.return_value.st_size = 1024
    mock_file.stat.return_value.st_mtime = 1600000000
    mock_dir.output_dir.glob.return_value = [mock_file]
    cli.ResultManager().view_results()


@patch("edgewalker.utils.get_input", side_effect=[""])
@patch("edgewalker.cli.controller.settings")
def test_run_credential_scan_no_target(mock_settings, mock_input, tmp_path):
    mock_settings.output_dir = tmp_path
    assert cli.run_credential_scan() is None


@patch("edgewalker.utils.get_input", side_effect=["1.1.1.1", "invalid"])
@patch("edgewalker.core.scanner_service.password_scan.scan", new_callable=AsyncMock)
@patch("edgewalker.core.scanner_service.save_results")
@patch("edgewalker.cli.controller.settings")
def test_run_credential_scan_invalid_top_n(
    mock_settings, mock_save, mock_scan, mock_input, tmp_path
):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel

    mock_settings.output_dir = tmp_path
    # Create dummy port scan results
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(
        '{"id": "test", "device_id": "test", "version": "0.1.0", "module": "port_scan", "module_version": "0.1.0", "hosts": [{"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00"}]}'
    )

    mock_scan.return_value = PasswordScanModel(
        hosts=[],
        results=[],
        summary={
            "vulnerable_hosts": 0,
            "total_hosts": 0,
            "services_tested": 0,
            "credentials_found": 0,
        },
    )
    cli.run_credential_scan()
    assert mock_scan.called


@patch("edgewalker.cli.controller.settings")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data='{"id": "test", "device_id": "test", "version": "0.1.0", "module": "port_scan", "module_version": "0.1.0", "hosts": [{"ip": "1.1.1.1", "state": "down", "mac": "00:00:00:00:00:00"}]}',
)
def test_run_cve_scan_no_up_hosts(mock_file, mock_settings):
    mock_port_file = MagicMock()
    mock_port_file.exists.return_value = True
    mock_settings.output_dir.__truediv__.return_value = mock_port_file
    assert cli.run_cve_scan() is None


@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch(
    "edgewalker.cli.controller.ScanController.run_port_scan",
    new_callable=AsyncMock,
    return_value={"hosts": [{"state": "down"}]},
)
@patch("edgewalker.utils.press_enter")
def test_automatic_mode_no_up_hosts(mock_press, mock_run, mock_input):
    with patch("edgewalker.cli.guided.GuidedScanner._show_scan_type_selection", return_value=False):
        controller = cli.ScanController()
        guided = cli.GuidedScanner(controller)
        cli.automatic_mode()
        assert mock_run.called


@patch("edgewalker.utils.get_input", side_effect=["3", "y", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.cli.controller.ScanController.run_port_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_full_scan_confirm(
    mock_press,
    mock_build,
    mock_prompt,
    mock_run,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_input,
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()
    assert mock_run.called


@patch("edgewalker.utils.get_input", side_effect=["4", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_creds_confirm(
    mock_press,
    mock_build,
    mock_prompt,
    mock_run,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_input,
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()
    assert mock_run.called


@patch("edgewalker.utils.get_input", side_effect=["5", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.display.build_status_panel")
@patch("edgewalker.utils.press_enter")
def test_interactive_mode_manual_cve_confirm(
    mock_press,
    mock_build,
    mock_prompt,
    mock_run,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_input,
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()
    assert mock_run.called


@patch("edgewalker.utils.get_input", side_effect=["1", "0"])
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection", side_effect=["manual", "exit"])
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_report_confirm(
    mock_build,
    mock_press,
    mock_risk,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_input,
):
    mock_build.return_value = MagicMock()
    cli.interactive_mode()
    assert mock_risk.called


@patch("edgewalker.utils.get_input", side_effect=["1.1.1.1", "10"])
@patch("edgewalker.core.scanner_service.password_scan.scan", new_callable=AsyncMock)
@patch("edgewalker.core.scanner_service.save_results")
@patch("edgewalker.cli.controller.settings")
def test_run_credential_scan_target_provided(
    mock_settings, mock_save, mock_scan, mock_input, tmp_path
):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel

    mock_settings.output_dir = tmp_path
    # Create dummy port scan results
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(
        '{"id": "test", "device_id": "test", "version": "0.1.0", "module": "port_scan", "module_version": "0.1.0", "hosts": [{"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00"}]}'
    )

    mock_scan.return_value = PasswordScanModel(
        hosts=[],
        results=[],
        summary={
            "vulnerable_hosts": 0,
            "total_hosts": 0,
            "services_tested": 0,
            "credentials_found": 0,
        },
    )
    cli.run_credential_scan(target="1.1.1.1")
    assert mock_scan.called


@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.utils.get_input", side_effect=["1", "", "0"])
@patch("edgewalker.cli.results.settings")
@patch("builtins.open", new_callable=mock_open, read_data='{"test": "data"}')
def test_view_results_select_success(mock_file, mock_dir, mock_input, mock_any):
    mock_dir.output_dir.exists.return_value = True
    mock_file = MagicMock()
    mock_file.name = "test.json"
    mock_file.stat.return_value.st_size = 1024
    mock_file.stat.return_value.st_mtime = 1600000000
    mock_dir.output_dir.glob.return_value = [mock_file]
    cli.ResultManager().view_results()
