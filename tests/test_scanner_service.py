# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

# Third Party
import pytest

# First Party
from edgewalker.core.scanner_service import ScannerService, submit_scan_data
from edgewalker.modules.port_scan.models import PortScanModel


@pytest.fixture
def scanner_service():
    service = ScannerService()
    # Patch _submit_telemetry to avoid background task warnings in tests that don't test it
    service._submit_telemetry = AsyncMock()
    return service


def test_scanner_service_init():
    progress_cb = MagicMock()
    telemetry_cb = MagicMock()
    service = ScannerService(progress_callback=progress_cb, telemetry_callback=telemetry_cb)
    assert service.progress_callback == progress_cb
    assert service.telemetry_callback == telemetry_cb


def test_notify(scanner_service):
    cb = MagicMock()
    scanner_service.progress_callback = cb
    scanner_service._notify("test", "message")
    cb.assert_called_once_with("test", "message")


@pytest.mark.asyncio
async def test_submit_telemetry_disabled():
    scanner_service = ScannerService()
    cb = MagicMock()
    scanner_service.telemetry_callback = cb
    with patch.object(scanner_service.telemetry, "is_telemetry_enabled", return_value=False):
        await scanner_service._submit_telemetry("test", {})
        cb.assert_called_once_with("disabled")


@pytest.mark.asyncio
async def test_submit_telemetry_success():
    scanner_service = ScannerService()
    cb = MagicMock()
    scanner_service.telemetry_callback = cb
    mock_response = MagicMock()
    mock_response.status_code = 201
    with patch.object(scanner_service.telemetry, "is_telemetry_enabled", return_value=True):
        with patch.object(
            scanner_service.telemetry,
            "submit_scan_data",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            await scanner_service._submit_telemetry("test", {})
            cb.assert_any_call("sending")
            cb.assert_any_call("success")


@pytest.mark.asyncio
async def test_submit_telemetry_error():
    scanner_service = ScannerService()
    cb = MagicMock()
    scanner_service.telemetry_callback = cb
    mock_response = MagicMock()
    mock_response.status_code = 500
    with patch.object(scanner_service.telemetry, "is_telemetry_enabled", return_value=True):
        with patch.object(
            scanner_service.telemetry,
            "submit_scan_data",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            await scanner_service._submit_telemetry("test", {})
            cb.assert_any_call("error")


def test_submit_scan_data_sync(scanner_service):
    with patch.object(scanner_service.telemetry, "submit_scan_data_sync") as mock_sync:
        scanner_service.submit_scan_data("test", {})
        mock_sync.assert_called_once()


@pytest.mark.asyncio
async def test_perform_port_scan_quick(scanner_service):
    mock_results = PortScanModel(success=True, target="1.1.1.1")
    with patch(
        "edgewalker.modules.port_scan.quick_scan", new_callable=AsyncMock, return_value=mock_results
    ):
        with patch("edgewalker.core.scanner_service.save_results") as mock_save:
            res = await scanner_service.perform_port_scan("1.1.1.1", full=False)
            assert res == mock_results
            assert mock_save.call_count == 2


@pytest.mark.asyncio
async def test_perform_port_scan_full(scanner_service):
    mock_results = PortScanModel(success=True, target="1.1.1.1")
    with patch(
        "edgewalker.modules.port_scan.full_scan", new_callable=AsyncMock, return_value=mock_results
    ):
        with patch("edgewalker.core.scanner_service.save_results") as mock_save:
            res = await scanner_service.perform_port_scan("1.1.1.1", full=True)
            assert res == mock_results
            assert mock_save.call_count == 2


@pytest.mark.asyncio
async def test_perform_port_scan_fail(scanner_service):
    mock_results = PortScanModel(success=False, error="Failed")
    with patch(
        "edgewalker.modules.port_scan.quick_scan", new_callable=AsyncMock, return_value=mock_results
    ):
        with pytest.raises(ValueError, match="Failed"):
            await scanner_service.perform_port_scan("1.1.1.1")


@pytest.mark.asyncio
async def test_perform_credential_scan_no_hosts(scanner_service):
    port_results = PortScanModel(hosts=[])
    res = await scanner_service.perform_credential_scan(port_results)
    assert res.results == []


@pytest.mark.asyncio
async def test_perform_credential_scan_with_hosts(scanner_service):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel
    from edgewalker.modules.port_scan.models import Host

    host = Host(ip="1.1.1.1", mac="00:11:22:33:44:55", state="up")
    port_results = PortScanModel(hosts=[host])
    mock_pass_results = PasswordScanModel(results=[])

    with patch(
        "edgewalker.modules.password_scan.scan",
        new_callable=AsyncMock,
        return_value=mock_pass_results,
    ):
        with patch("edgewalker.core.scanner_service.save_results") as mock_save:
            res = await scanner_service.perform_credential_scan(port_results)
            assert res == mock_pass_results
            assert mock_save.call_count == 2


@pytest.mark.asyncio
async def test_perform_cve_scan_no_hosts(scanner_service):
    port_results = PortScanModel(hosts=[])
    with pytest.raises(ValueError, match="No hosts found"):
        await scanner_service.perform_cve_scan(port_results)


@pytest.mark.asyncio
async def test_perform_cve_scan_with_hosts(scanner_service):
    # First Party
    from edgewalker.modules.cve_scan.models import CveScanModel
    from edgewalker.modules.port_scan.models import Host

    host = Host(ip="1.1.1.1", mac="00:11:22:33:44:55", state="up")
    port_results = PortScanModel(hosts=[host])
    mock_cve_results = CveScanModel(results=[])

    with patch(
        "edgewalker.modules.cve_scan.scan", new_callable=AsyncMock, return_value=mock_cve_results
    ):
        with patch("edgewalker.core.scanner_service.save_results") as mock_save:
            res = await scanner_service.perform_cve_scan(port_results)
            assert res == mock_cve_results
            assert mock_save.call_count == 2


def test_submit_scan_data_async(scanner_service):
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop_instance = MagicMock()
        mock_loop.return_value = mock_loop_instance
        scanner_service.submit_scan_data("test", {})
        mock_loop_instance.create_task.assert_called_once()


@pytest.mark.asyncio
async def test_perform_port_scan_dict_results(scanner_service):
    mock_results_dict = {"success": True, "target": "1.1.1.1"}
    with patch(
        "edgewalker.modules.port_scan.quick_scan",
        new_callable=AsyncMock,
        return_value=mock_results_dict,
    ):
        with patch("edgewalker.core.scanner_service.save_results"):
            res = await scanner_service.perform_port_scan("1.1.1.1")
            assert isinstance(res, PortScanModel)
            assert res.target == "1.1.1.1"


@pytest.mark.asyncio
async def test_perform_credential_scan_from_file(scanner_service):
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanModel

    port_data = {"hosts": [{"ip": "1.1.1.1", "mac": "00:11:22:33:44:55", "state": "up"}]}
    mock_pass_results = PasswordScanModel(results=[])

    with patch("pathlib.Path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=json.dumps(port_data))):
            with patch(
                "edgewalker.modules.password_scan.scan",
                new_callable=AsyncMock,
                return_value=mock_pass_results,
            ):
                with patch("edgewalker.core.scanner_service.save_results"):
                    res = await scanner_service.perform_credential_scan()
                    assert res == mock_pass_results


@pytest.mark.asyncio
async def test_perform_cve_scan_from_file(scanner_service):
    # First Party
    from edgewalker.modules.cve_scan.models import CveScanModel

    port_data = {"hosts": [{"ip": "1.1.1.1", "mac": "00:11:22:33:44:55", "state": "up"}]}
    mock_cve_results = CveScanModel(results=[])

    with patch("pathlib.Path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=json.dumps(port_data))):
            with patch(
                "edgewalker.modules.cve_scan.scan",
                new_callable=AsyncMock,
                return_value=mock_cve_results,
            ):
                with patch("edgewalker.core.scanner_service.save_results"):
                    res = await scanner_service.perform_cve_scan()
                    assert res == mock_cve_results


def test_global_submit_scan_data_async():
    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop_instance = MagicMock()
        mock_loop.return_value = mock_loop_instance
        submit_scan_data("test", {})
        mock_loop_instance.create_task.assert_called_once()
