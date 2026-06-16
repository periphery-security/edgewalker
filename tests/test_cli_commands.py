# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
from typer.testing import CliRunner

# First Party
from edgewalker.cli.cli import app

runner = CliRunner()


def test_cli_config_show():
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "EDGEWALKER CONFIGURATION" in result.stdout


def test_cli_config_set():
    with patch("edgewalker.cli.cli.update_setting") as mock_update:
        result = runner.invoke(app, ["config", "set", "telemetry_enabled", "False"])
        assert result.exit_code == 0
        assert "Successfully updated" in result.stdout
        mock_update.assert_called_with("telemetry_enabled", "False")


def test_cli_config_path():
    result = runner.invoke(app, ["config", "path"])
    assert result.exit_code == 0
    # Remove newlines to handle wrapping in some environments
    clean_stdout = result.stdout.replace("\n", "").replace("\r", "")
    assert "config.yaml" in clean_stdout


def test_cli_report():
    with patch("edgewalker.cli.cli.ScanController.view_device_risk") as mock_view:
        result = runner.invoke(app, ["report"])
        assert result.exit_code == 0
        assert mock_view.called


def test_cli_results():
    with patch("edgewalker.cli.cli.ResultManager.view_results") as mock_view:
        result = runner.invoke(app, ["results"])
        assert result.exit_code == 0
        assert mock_view.called


def test_cli_findings_empty():
    """findings prints the empty-state when there is no scan data."""
    with patch("edgewalker.cli.cli.Engine.load_report_inputs", return_value={}):
        result = runner.invoke(app, ["findings"])
        assert result.exit_code == 0
        assert "No assessment yet" in result.stdout


def test_cli_findings_lists_findings(tmp_path):
    """findings renders the prioritised list from build_summary."""
    # First Party
    from edgewalker.core.findings import AssessmentSummary, Finding

    summary = AssessmentSummary(
        grade="F",
        grade_reason="Default credentials found.",
        score=85,
        target="192.168.1.0/24",
        device_count=1,
        open_ports=2,
        gateway_ip="192.168.1.1",
        devices_with_creds=1,
        findings=[Finding("CRITICAL", "Default credentials", "192.168.1.42", "admin / admin")],
        devices=[],
    )
    with patch("edgewalker.core.findings.build_summary", return_value=summary):
        result = runner.invoke(app, ["findings"])
        assert result.exit_code == 0
        assert "Default credentials" in result.stdout


def test_cli_clear():
    with patch("edgewalker.cli.cli.ResultManager.clear_results") as mock_clear:
        result = runner.invoke(app, ["clear"])
        assert result.exit_code == 0
        assert mock_clear.called


def test_cli_scan():
    with patch(
        "edgewalker.cli.cli.GuidedScanner.automatic_mode", return_value=MagicMock()
    ) as mock_auto:
        # automatic_mode is async, but it's called with asyncio.run
        # We need to mock it to return a coroutine or just mock the whole thing
        mock_auto.return_value = (
            MagicMock()
        )  # Not really a coroutine but asyncio.run might handle it if we mock it right

        with patch("asyncio.run") as mock_run:
            result = runner.invoke(app, ["scan", "--target", "127.0.0.1"])
            assert result.exit_code == 0
            assert mock_run.called


def test_cli_tui():
    with patch("edgewalker.cli.cli.EdgeWalkerApp.run") as mock_run:
        result = runner.invoke(app, ["tui"])
        assert result.exit_code == 0
        assert mock_run.called


def test_cli_main_callback():
    result = runner.invoke(app, ["--verbose", "config", "path"])
    assert result.exit_code == 0
