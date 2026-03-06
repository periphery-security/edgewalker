# Standard Library
import asyncio
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

# Third Party
import pytest
from typer.testing import CliRunner

# First Party
from edgewalker import cli
from edgewalker.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def mock_settings_dir(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    old_dir = settings.output_dir
    settings.output_dir = tmp_path
    yield settings
    settings.output_dir = old_dir


@pytest.fixture
def mock_results():
    # First Party
    from edgewalker.modules.port_scan.models import PortScanModel

    return PortScanModel(
        id="test-id",
        device_id="test-device",
        version="0.1.0",
        module="port_scan",
        module_version="0.1.0",
        success=True,
        hosts=[
            {
                "ip": "1.1.1.1",
                "state": "up",
                "hostname": "test-host",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Test Vendor",
                "os": ["Linux"],
                "tcp": [
                    {"port": 80, "name": "http", "product_name": "Apache", "product_version": "2.4"}
                ],
            }
        ],
        target="1.1.1.1",
        scan_type="quick",
        hosts_responded=1,
        hosts_with_ports=1,
        all_ports=False,
        version_scan=False,
        error=None,
    )


@pytest.mark.asyncio
@patch("edgewalker.core.scanner_service.port_scan.quick_scan", new_callable=AsyncMock)
@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch("edgewalker.core.scanner_service.save_results", return_value="path")
@patch("edgewalker.core.scanner_service.submit_scan_data")
async def test_run_port_scan(mock_submit, mock_save, mock_input, mock_quick, mock_results):
    mock_quick.return_value = mock_results
    res = await cli.ScanController().run_port_scan(full=False)
    assert res.model_dump(mode="json") == mock_results.model_dump(mode="json")
    mock_quick.assert_called_once_with(target="1.1.1.1", verbose=False, progress_callback=None, unprivileged=False)


@pytest.mark.asyncio
@patch("edgewalker.core.scanner_service.port_scan.full_scan", new_callable=AsyncMock)
@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch("edgewalker.core.scanner_service.save_results", return_value="path")
@patch("edgewalker.core.scanner_service.submit_scan_data")
async def test_run_port_scan_full(mock_submit, mock_save, mock_input, mock_full, mock_results):
    mock_full.return_value = mock_results
    res = await cli.ScanController().run_port_scan(full=True)
    assert res.model_dump(mode="json") == mock_results.model_dump(mode="json")


@pytest.mark.asyncio
@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.cli.controller.ScanController.run_port_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.cli.guided.GuidedScanner._show_scan_type_selection", return_value=False)
@patch("edgewalker.utils.get_input", return_value="1.1.1.1")
@patch("edgewalker.utils.press_enter")
async def test_automatic_mode(
    mock_press,
    mock_input,
    mock_type,
    mock_risk,
    mock_cve,
    mock_pwd,
    mock_port,
    mock_status,
    mock_results,
):
    mock_status.return_value = {
        "port_scan": True,
        "port_scan_type": "quick",
        "password_scan": True,
        "cve_scan": True,
        "devices_found": 1,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    mock_port.return_value = mock_results

    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    await guided.automatic_mode()
    assert mock_port.called
    assert mock_pwd.called
    assert mock_cve.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
def test_interactive_mode_exit(mock_any, mock_telemetry_enabled, mock_mode, mock_input):
    mock_mode.return_value = "exit"
    cli.interactive_mode()
    mock_mode.assert_called_once()


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.cli.menu.InteractiveMenu._manual_mode", new_callable=AsyncMock)
def test_interactive_mode_manual_exit(
    mock_manual, mock_any, mock_telemetry_enabled, mock_mode, mock_input
):
    # First call to show_mode_selection returns "manual"
    # Choice "0" in manual menu returns from interactive_mode immediately
    mock_mode.side_effect = ["manual", "exit"]
    mock_input.side_effect = ["0"]  # Exit manual menu (returns from function)
    cli.interactive_mode()
    assert mock_mode.call_count == 2


@patch("edgewalker.utils.print_logo")
@patch("edgewalker.cli.cli.GuidedScanner")
def test_typer_scan(mock_guided_cls, mock_logo):
    mock_guided = mock_guided_cls.return_value
    mock_guided.automatic_mode = AsyncMock()
    result = runner.invoke(app, ["scan", "--target", "1.1.1.1"])
    assert result.exit_code == 0
    mock_guided.automatic_mode.assert_called_once_with(
        full_scan=False, target="1.1.1.1", full_creds=False, unprivileged=False, verbose=False
    )


@patch("edgewalker.cli.cli.GuidedScanner")
def test_typer_scan_full(mock_guided_cls):
    mock_guided = mock_guided_cls.return_value
    mock_guided.automatic_mode = AsyncMock()
    result = runner.invoke(app, ["scan", "--full", "-t", "1.1.1.1", "--full-creds"])
    assert result.exit_code == 0
    mock_guided.automatic_mode.assert_called_once_with(
        full_scan=True, target="1.1.1.1", full_creds=True, unprivileged=False, verbose=False
    )


@patch("edgewalker.cli.cli.GuidedScanner")
def test_typer_scan_full_creds(mock_guided_cls):
    mock_guided = mock_guided_cls.return_value
    mock_guided.automatic_mode = AsyncMock()
    result = runner.invoke(app, ["scan", "--full-creds", "-t", "1.1.1.1"])
    assert result.exit_code == 0
    mock_guided.automatic_mode.assert_called_once_with(
        full_scan=False, target="1.1.1.1", full_creds=True, unprivileged=False, verbose=False
    )


@patch("edgewalker.cli.controller.ScanController.view_device_risk")
def test_typer_report(mock_view):
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 0
    assert mock_view.called


@patch("edgewalker.cli.results.ResultManager.view_results")
def test_typer_results(mock_view):
    result = runner.invoke(app, ["results"])
    assert result.exit_code == 0
    mock_view.assert_called_once_with(interactive=True)


@patch("edgewalker.cli.results.ResultManager.clear_results")
def test_typer_clear(mock_clear):
    result = runner.invoke(app, ["clear"])
    assert result.exit_code == 0
    mock_clear.assert_called_once_with(interactive=False)


@patch("edgewalker.tui.app.EdgeWalkerApp.run")
def test_typer_tui(mock_run):
    result = runner.invoke(app, ["tui"])
    assert result.exit_code == 0
    assert mock_run.called


def test_view_device_risk(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    old_dir = settings.output_dir
    settings.output_dir = tmp_path
    try:
        port_file = tmp_path / "port_scan.json"
        port_file.write_text('{"hosts": []}')
        with patch(
            "edgewalker.cli.controller.build_risk_report", return_value=([], {})
        ) as mock_build:
            cli.ScanController().view_device_risk()
            assert mock_build.called
    finally:
        settings.output_dir = old_dir


@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.get_input", return_value="")
def test_view_results_empty(mock_input, mock_any):
    cli.ResultManager().view_results()
    assert mock_any.called


@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.cli.results.settings")
@patch("edgewalker.utils.get_input", return_value="y")
def test_clear_results(mock_input, mock_settings, mock_any):
    mock_settings.output_dir.exists.return_value = True
    mock_settings.output_dir.glob.return_value = [MagicMock()]
    cli.ResultManager().clear_results()
    assert mock_settings.output_dir.glob.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.controller.ScanController.run_port_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_scan(
    mock_build, mock_any, mock_telemetry_enabled, mock_mode, mock_prompt, mock_run, mock_input
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    mock_input.side_effect = ["2", "0"]
    cli.interactive_mode()
    assert mock_run.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_creds(
    mock_build,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_prompt,
    mock_run,
    mock_input,
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    mock_input.side_effect = ["4", "0"]
    cli.interactive_mode()
    assert mock_run.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock)
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_cve(
    mock_build,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_prompt,
    mock_run,
    mock_input,
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    mock_input.side_effect = ["5", "0"]
    cli.interactive_mode()
    assert mock_run.called


@pytest.mark.asyncio
@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", return_value="y")
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.utils.press_enter")
async def test_prompt_next_scan_all_complete(mock_press, mock_risk, mock_input, mock_status):
    mock_status.return_value = {
        "port_scan": True,
        "password_scan": True,
        "cve_scan": True,
        "devices_found": 1,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    await guided.prompt_next_scan()
    assert mock_risk.called


@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.cli.results.settings")
@patch("edgewalker.utils.get_input", return_value="y")
@patch("edgewalker.utils.press_enter")
def test_check_previous_results_clear(mock_press, mock_input, mock_settings, mock_any):
    mock_file = MagicMock()
    mock_settings.output_dir.glob.return_value = [mock_file]
    cli.ResultManager().check_previous_results()
    assert mock_file.unlink.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.controller.ScanController.view_device_risk")
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=False)
@patch("edgewalker.utils.has_port_scan", return_value=True)
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_report(
    mock_build,
    mock_press,
    mock_has,
    mock_any,
    mock_telemetry_enabled,
    mock_mode,
    mock_view,
    mock_input,
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    mock_input.side_effect = ["1", "0"]
    cli.interactive_mode()
    assert mock_view.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.results.ResultManager.view_results")
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_raw(
    mock_build, mock_press, mock_any, mock_telemetry_enabled, mock_mode, mock_view, mock_input
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    # 1. check_previous_results (has_any_results=True)
    # 2. Manual menu choice "8"
    # 3. Manual menu choice "0" (Exit)
    mock_input.side_effect = ["n", "8", "0"]
    cli.interactive_mode()
    assert mock_view.called


@patch("edgewalker.utils.get_input")
@patch("edgewalker.cli.results.ResultManager.clear_results")
@patch("edgewalker.cli.menu.InteractiveMenu._show_mode_selection")
@patch("edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True)
@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.utils.press_enter")
@patch("edgewalker.display.build_status_panel")
def test_interactive_mode_manual_clear(
    mock_build, mock_press, mock_any, mock_telemetry_enabled, mock_mode, mock_clear, mock_input
):
    mock_build.return_value = MagicMock()
    mock_mode.side_effect = ["manual", "exit"]
    # 1. check_previous_results (has_any_results=True)
    # 2. Manual menu choice "9"
    # 3. Manual menu choice "0" (Exit)
    mock_input.side_effect = ["n", "9", "0"]
    cli.interactive_mode()
    assert mock_clear.called


@patch("edgewalker.utils.get_input", return_value="1")
@patch(
    "edgewalker.cli.controller.ScanController.run_port_scan",
    new_callable=AsyncMock,
    return_value=None,
)
@patch("edgewalker.utils.press_enter")
def test_automatic_mode_fail(mock_press, mock_run, mock_input):
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    asyncio.run(guided.automatic_mode())
    assert mock_run.called


@patch("edgewalker.utils.get_input", return_value="1")
@patch(
    "edgewalker.cli.controller.ScanController.run_port_scan",
    new_callable=AsyncMock,
    return_value={"hosts": []},
)
@patch("edgewalker.utils.press_enter")
def test_automatic_mode_no_hosts(mock_press, mock_run, mock_input):
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    asyncio.run(guided.automatic_mode())
    assert mock_run.called


@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", return_value="y")
@patch("edgewalker.cli.controller.ScanController.run_credential_scan", new_callable=AsyncMock)
def test_prompt_next_scan_suggest_creds(mock_run, mock_input, mock_status):
    mock_status.return_value = {
        "port_scan": True,
        "password_scan": False,
        "cve_scan": False,
        "devices_found": 1,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    # We need to call the original function but patch the recursive call
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    original_prompt = guided.prompt_next_scan
    with patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock):
        asyncio.run(original_prompt())
    assert mock_run.called


@patch("edgewalker.utils.get_scan_status")
@patch("edgewalker.utils.get_input", return_value="y")
@patch("edgewalker.cli.controller.ScanController.run_cve_scan", new_callable=AsyncMock)
def test_prompt_next_scan_suggest_cve(mock_run, mock_input, mock_status):
    mock_status.return_value = {
        "port_scan": True,
        "password_scan": True,
        "cve_scan": False,
        "devices_found": 1,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    controller = cli.ScanController()
    guided = cli.GuidedScanner(controller)
    original_prompt = guided.prompt_next_scan
    with patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock):
        asyncio.run(original_prompt())
    assert mock_run.called


@patch("edgewalker.cli.guided.GuidedScanner.automatic_mode", new_callable=AsyncMock)
@patch("edgewalker.utils.ensure_telemetry_choice")
def test_run_guided_scan_verbose_flag(mock_telemetry, mock_auto):
    """--verbose flag is accepted and passed through to automatic_mode."""
    result = runner.invoke(app, ["scan", "--verbose", "--target", "1.1.1.1"])
    assert result.exit_code == 0
    mock_auto.assert_called_once()
    _, kwargs = mock_auto.call_args
    assert kwargs.get("verbose") is True


@patch("edgewalker.cli.guided.GuidedScanner.automatic_mode", new_callable=AsyncMock)
@patch("edgewalker.utils.ensure_telemetry_choice")
def test_run_guided_scan_unprivileged_flag(mock_telemetry, mock_auto):
    """--unprivileged flag is accepted and passed through to automatic_mode."""
    result = runner.invoke(app, ["scan", "--unprivileged", "--target", "1.1.1.1"])
    assert result.exit_code == 0
    mock_auto.assert_called_once()
    _, kwargs = mock_auto.call_args
    assert kwargs.get("unprivileged") is True


@patch("edgewalker.utils.has_any_results", return_value=True)
@patch("edgewalker.cli.results.settings")
@patch("edgewalker.utils.get_input", side_effect=["1", "", "0"])
@patch("edgewalker.utils.press_enter")
@patch("builtins.open", new_callable=mock_open, read_data='{"test": "data"}')
def test_view_results_select(mock_file, mock_press, mock_input, mock_settings, mock_any):
    mock_file_obj = MagicMock()
    mock_file_obj.name = "test.json"
    mock_file_obj.stat.return_value.st_size = 1024
    mock_file_obj.stat.return_value.st_mtime = 1600000000
    mock_settings.output_dir.exists.return_value = True
    mock_settings.output_dir.glob.return_value = [mock_file_obj]
    cli.ResultManager().view_results(interactive=True)
    assert mock_file.called
