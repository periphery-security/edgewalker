# Standard Library
from unittest.mock import MagicMock, patch

# First Party
from edgewalker import cli


def test_cli_init_wrappers():
    with patch(
        "edgewalker.cli.GuidedScanner.automatic_mode", return_value=MagicMock()
    ) as mock_auto:
        with patch("asyncio.run"):
            cli.automatic_mode()
            assert mock_auto.called

    with patch(
        "edgewalker.cli.GuidedScanner.prompt_next_scan", return_value=MagicMock()
    ) as mock_prompt:
        with patch("asyncio.run"):
            cli.prompt_next_scan()
            assert mock_prompt.called

    with patch(
        "edgewalker.cli.ScanController.run_port_scan", return_value=MagicMock()
    ) as mock_port:
        with patch("asyncio.run"):
            cli.run_port_scan()
            assert mock_port.called

    with patch(
        "edgewalker.cli.ScanController.run_credential_scan", return_value=MagicMock()
    ) as mock_cred:
        with patch("asyncio.run"):
            cli.run_credential_scan()
            assert mock_cred.called

    with patch("edgewalker.cli.ScanController.run_cve_scan", return_value=MagicMock()) as mock_cve:
        with patch("asyncio.run"):
            cli.run_cve_scan()
            assert mock_cve.called

    with patch("edgewalker.cli.ScanController.view_device_risk") as mock_risk:
        cli.view_device_risk()
        assert mock_risk.called
