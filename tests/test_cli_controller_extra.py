# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker import __version__
from edgewalker.cli.controller import ScanController
from edgewalker.core.scanner_service import ScannerService
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel
from edgewalker.modules.sql_scan.models import SqlScanModel
from edgewalker.modules.web_scan.models import WebScanModel


@pytest.mark.asyncio
async def test_controller_sql_scan():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_sql_scan = AsyncMock(
        return_value=SqlScanModel(
            id="test-id", device_id="test-device", version=__version__, results=[], summary={}
        )
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    results = await controller.run_sql_scan(port_results=port_results)
    assert results is not None
    assert scanner.perform_sql_scan.called


@pytest.mark.asyncio
async def test_controller_web_scan():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_web_scan = AsyncMock(
        return_value=WebScanModel(
            id="test-id", device_id="test-device", version=__version__, results=[], summary={}
        )
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    results = await controller.run_web_scan(port_results=port_results)
    assert results is not None
    assert scanner.perform_web_scan.called


@pytest.mark.asyncio
async def test_controller_port_scan_error():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_port_scan.side_effect = Exception("Scan error")

    controller = ScanController(scanner_service=scanner)
    with patch("edgewalker.utils.get_input", return_value="127.0.0.1"):
        results = await controller.run_port_scan()
        assert results is None


@pytest.mark.asyncio
async def test_controller_credential_scan_no_results(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path

    controller = ScanController()
    results = await controller.run_credential_scan(port_results=None, interactive=False)
    assert results is None


@pytest.mark.asyncio
async def test_controller_credential_scan_load_file(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path

    port_file = tmp_path / "port_scan.json"
    port_file.write_text(json.dumps({"hosts": [], "summary": {}}))

    scanner = MagicMock(spec=ScannerService)
    scanner.perform_credential_scan = AsyncMock(
        return_value=PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})
    )

    controller = ScanController(scanner_service=scanner)
    results = await controller.run_credential_scan(port_results=None, interactive=False)
    assert results is not None


@pytest.mark.asyncio
async def test_controller_credential_scan_interactive_all():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_credential_scan = AsyncMock(
        return_value=PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    with patch("edgewalker.utils.get_input", return_value="all"):
        results = await controller.run_credential_scan(port_results=port_results, interactive=True)
        assert results is not None
        scanner.perform_credential_scan.assert_called_with(port_results=port_results, top_n=None)


@pytest.mark.asyncio
async def test_controller_credential_scan_interactive_invalid():
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_credential_scan = AsyncMock(
        return_value=PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})
    )

    controller = ScanController(scanner_service=scanner)
    port_results = PortScanModel(hosts=[], summary={"total_hosts": 0})

    with patch("edgewalker.utils.get_input", return_value="invalid"):
        results = await controller.run_credential_scan(port_results=port_results, interactive=True)
        assert results is not None
        # Should default to 10
        scanner.perform_credential_scan.assert_called_with(port_results=port_results, top_n=10)


def test_controller_view_risk_no_file(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path

    controller = ScanController()
    controller.view_device_risk()
    # Should just return/log error
