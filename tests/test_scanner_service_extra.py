# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
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
