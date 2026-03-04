# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import httpx
import pytest

# First Party
from edgewalker.modules.cve_scan.scanner import CveScanner, search_cves_async


@pytest.mark.asyncio
async def test_search_cves_async():
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }
    mock_client.get = AsyncMock(return_value=mock_response)

    cves = await search_cves_async(mock_client, "Apache", "2.4")
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2026-0001"
    assert cves[0]["score"] == 9.8


@pytest.mark.asyncio
async def test_cve_scanner_hosts():
    scanner = CveScanner()
    hosts = [{"ip": "127.0.0.1", "tcp": [{"port": 80, "product": "Apache", "version": "2.4"}]}]

    with patch(
        "edgewalker.modules.cve_scan.scanner.search_cves_async", new_callable=AsyncMock
    ) as mock_search:
        mock_search.return_value = [{"id": "CVE-1", "severity": "HIGH", "score": 7.5}]
        results = await scanner.scan_hosts(hosts)
        assert results.summary["total_cves"] == 1
