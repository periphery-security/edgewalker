# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner
from edgewalker.core.engine import PhaseResult
from edgewalker.modules.port_scan.models import Host, PortScanModel


@pytest.mark.asyncio
async def test_guided_automatic_mode():
    controller = MagicMock(spec=ScanController)
    controller.view_device_risk = MagicMock()

    port_model = PortScanModel(hosts=[Host(ip="127.0.0.1", mac="00:00:00:00:00:00", state="up")])

    async def fake_run_assessment(opts, *, port_results=None):
        yield PhaseResult("port", port_model)
        yield PhaseResult("credential", MagicMock())
        yield PhaseResult("cve", MagicMock())
        yield PhaseResult("sql", MagicMock())
        yield PhaseResult("web", MagicMock())

    guided = GuidedScanner(controller)
    guided.engine.run_assessment = fake_run_assessment
    # Rendering is exercised separately; keep this focused on sequencing.
    guided._render_phase = MagicMock()

    with patch("edgewalker.utils.get_input", side_effect=["1", "127.0.0.1"]):
        with patch("edgewalker.utils.clear_screen"):
            with patch("edgewalker.utils.print_logo"):
                await guided.automatic_mode()

    assert guided._render_phase.call_count == 5
    controller.view_device_risk.assert_called_once()


@pytest.mark.asyncio
async def test_guided_automatic_mode_no_hosts_skips_report():
    controller = MagicMock(spec=ScanController)
    controller.view_device_risk = MagicMock()

    empty_port_model = PortScanModel(hosts=[])

    async def fake_run_assessment(opts, *, port_results=None):
        yield PhaseResult("port", empty_port_model)

    guided = GuidedScanner(controller)
    guided.engine.run_assessment = fake_run_assessment
    guided._render_phase = MagicMock()

    with patch("edgewalker.utils.get_input", side_effect=["1", "127.0.0.1"]):
        with patch("edgewalker.utils.clear_screen"):
            with patch("edgewalker.utils.print_logo"):
                with patch("edgewalker.utils.press_enter"):
                    await guided.automatic_mode()

    controller.view_device_risk.assert_not_called()


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
