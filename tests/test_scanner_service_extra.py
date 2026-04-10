# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker import __version__
from edgewalker.core.scanner_service import ScannerService
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel


@pytest.mark.asyncio
async def test_scanner_service_notify():
    callback = MagicMock()
    service = ScannerService(progress_callback=callback)
    service._notify("test", "message")
    callback.assert_called_with("test", "message")


@pytest.mark.asyncio
async def test_scanner_service_submit_telemetry():
    service = ScannerService()
    with patch.object(service.telemetry, "is_telemetry_enabled", return_value=True):
        with patch.object(
            service.telemetry, "submit_scan_data", new_callable=AsyncMock
        ) as mock_submit:
            mock_submit.return_value = MagicMock(status_code=201)
            await service._submit_telemetry("test", {})
            assert mock_submit.called


@pytest.mark.asyncio
async def test_scanner_service_port_scan():
    service = ScannerService()
    mock_results = PortScanModel(success=True, hosts=[], summary={"total_hosts": 0})

    with patch("edgewalker.modules.port_scan.quick_scan", new_callable=AsyncMock) as mock_quick:
        mock_quick.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_port_scan("127.0.0.1")
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_credential_scan():
    service = ScannerService()
    port_results = PortScanModel(
        hosts=[{"ip": "127.0.0.1", "state": "up", "mac": "00:00:00:00:00:00", "tcp": []}],
        summary={"total_hosts": 1},
    )
    mock_results = PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})

    with patch("edgewalker.modules.password_scan.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_credential_scan(port_results=port_results)
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_cve_scan():
    service = ScannerService()
    port_results = PortScanModel(
        hosts=[{"ip": "127.0.0.1", "state": "up", "mac": "00:00:00:00:00:00", "tcp": []}],
        summary={"total_hosts": 1},
    )
    mock_results = CveScanModel(results=[], summary={"total_cves": 0})

    with patch("edgewalker.modules.cve_scan.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_cve_scan(port_results=port_results)
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_port_scan_full():
    service = ScannerService()
    mock_results = PortScanModel(success=True, hosts=[], summary={"total_hosts": 0})

    with patch("edgewalker.modules.port_scan.full_scan", new_callable=AsyncMock) as mock_full:
        mock_full.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_port_scan("127.0.0.1", full=True)
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_sql_scan():
    # First Party
    from edgewalker.modules.sql_scan.models import SqlScanModel

    service = ScannerService()
    port_results = PortScanModel(
        hosts=[{"ip": "127.0.0.1", "state": "up", "mac": "00:00:00:00:00:00", "tcp": []}],
        summary={"total_hosts": 1},
    )
    mock_results = SqlScanModel(
        id="test-id",
        device_id="test-device",
        version=__version__,
        results=[],
        summary={"vulnerable_services": 0},
    )

    with patch("edgewalker.modules.sql_scan.SqlScanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_sql_scan(port_results=port_results)
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_web_scan():
    # First Party
    from edgewalker.modules.web_scan.models import WebScanModel

    service = ScannerService()
    port_results = PortScanModel(
        hosts=[{"ip": "127.0.0.1", "state": "up", "mac": "00:00:00:00:00:00", "tcp": []}],
        summary={"total_hosts": 1},
    )
    mock_results = WebScanModel(
        id="test-id",
        device_id="test-device",
        version=__version__,
        results=[],
        summary={"total_services": 0},
    )

    with patch("edgewalker.modules.web_scan.WebScanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_results
        with patch("edgewalker.core.scanner_service.save_results"):
            with patch.object(service, "_submit_telemetry", new_callable=AsyncMock):
                results = await service.perform_web_scan(port_results=port_results)
                assert results == mock_results


@pytest.mark.asyncio
async def test_scanner_service_load_from_file(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path

    port_data = {"hosts": [], "summary": {"total_hosts": 0}, "success": True}
    (tmp_path / "port_scan.json").write_text(json.dumps(port_data))

    service = ScannerService()

    with patch("edgewalker.modules.password_scan.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = PasswordScanModel(results=[], summary={})
        with patch("edgewalker.core.scanner_service.save_results"):
            results = await service.perform_credential_scan(port_results=None)
            assert results is not None
