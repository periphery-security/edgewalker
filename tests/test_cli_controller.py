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


def test_view_risk_records_score_trend_point(tmp_path):
    """The report path lands a score-trend point (Issue 1 regression).

    Before the fix, only the guided CLI flow recorded an assessment; viewing
    the risk report (the `report` command / menu) recorded nothing.
    """
    # First Party
    from edgewalker.core.config import settings
    from edgewalker.core.sqlite_store import SqliteResultStore

    settings.output_dir = tmp_path
    (tmp_path / "port_scan.json").write_text(
        json.dumps({
            "target": "192.168.1.0/24",
            "hosts": [
                {
                    "ip": "192.168.1.42",
                    "mac": "00:00:00:00:00:00",
                    "vendor": "Acme",
                    "state": "up",
                    "tcp": [{"port": 23, "name": "telnet"}],
                }
            ],
            "summary": {},
        })
    )

    # Real ScannerService.from_env() store (SqliteResultStore at the isolated db_path).
    ScanController().view_device_risk()

    trend = SqliteResultStore(settings.db_path).score_trend()
    assert len(trend) == 1
    assert trend[0]["grade"]
