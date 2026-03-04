# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.cli.controller import ScanController
from edgewalker.core.scanner_service import ScannerService
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel


@pytest.mark.asyncio
async def test_controller_port_scan():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_port_scan = AsyncMock(
        return_value=PortScanModel(hosts=[], summary={"total_hosts": 0})
    )

    controller = ScanController(scanner_service=scanner)
    with patch("edgewalker.utils.get_input", return_value="127.0.0.1"):
        results = await controller.run_port_scan()
        assert results is not None
        assert scanner.perform_port_scan.called


@pytest.mark.asyncio
async def test_controller_credential_scan():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_credential_scan = AsyncMock(
        return_value=PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    with patch("edgewalker.utils.get_input", return_value="10"):
        results = await controller.run_credential_scan(port_results=port_results)
        assert results is not None
        assert scanner.perform_credential_scan.called


@pytest.mark.asyncio
async def test_controller_cve_scan():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_cve_scan = AsyncMock(
        return_value=CveScanModel(results=[], summary={"total_cves": 0})
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    results = await controller.run_cve_scan(port_results=port_results)
    assert results is not None
    assert scanner.perform_cve_scan.called


def test_controller_view_risk(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path

    port_file = tmp_path / "port_scan.json"
    port_file.write_text(json.dumps({"hosts": [], "summary": {}}))

    controller = ScanController()
    with patch("edgewalker.cli.controller.build_risk_report", return_value=([], {})):
        controller.view_device_risk()
