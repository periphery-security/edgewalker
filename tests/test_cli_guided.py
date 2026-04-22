# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner


@pytest.mark.asyncio
async def test_guided_automatic_mode():
    controller = MagicMock(spec=ScanController)
    controller.run_port_scan = AsyncMock(
        return_value={"hosts": [{"ip": "127.0.0.1", "state": "up"}]}
    )
    controller.run_credential_scan = AsyncMock()
    controller.run_cve_scan = AsyncMock()

    guided = GuidedScanner(controller)

    with patch("edgewalker.utils.get_input", side_effect=["1", "127.0.0.1"]):
        with patch("edgewalker.utils.clear_screen"):
            with patch("edgewalker.utils.print_logo"):
                await guided.automatic_mode()
                assert controller.run_port_scan.called
                assert controller.run_credential_scan.called
                assert controller.run_cve_scan.called


@pytest.mark.asyncio
async def test_guided_prompt_next():
    controller = MagicMock(spec=ScanController)
    controller.run_credential_scan = AsyncMock()

    guided = GuidedScanner(controller)

    # First call: port_scan=True, password_scan=False -> suggests password scan
    # Second call: all True -> shows "All scans complete"
    with patch(
        "edgewalker.utils.get_scan_status",
        side_effect=[
            {
                "port_scan": True,
                "password_scan": False,
                "cve_scan": False,
                "sql_scan": False,
                "web_scan": False,
            },
            {
                "port_scan": True,
                "password_scan": True,
                "cve_scan": True,
                "sql_scan": True,
                "web_scan": True,
                "devices_found": 1,
                "vulnerable_devices": 0,
                "cves_found": 0,
                "sql_vulns": 0,
                "web_vulns": 0,
            },
        ],
    ):
        with patch("edgewalker.utils.get_input", return_value="y"):
            with patch("edgewalker.utils.press_enter"):
                await guided.prompt_next_scan()
                assert controller.run_credential_scan.called


def test_guided_scan_type_selection():
    guided = GuidedScanner(MagicMock())
    with patch("edgewalker.utils.get_input", return_value="2"):
        assert guided._show_scan_type_selection() is True
