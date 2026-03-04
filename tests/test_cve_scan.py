# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.cve_scan import scanner


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_search_cves_success(mock_search_async):
    """Test successful CVE search."""
    mock_search_async.return_value = [
        {
            "id": "CVE-2023-0001",
            "description": "Test vulnerability",
            "severity": "CRITICAL",
            "score": 9.8,
        }
    ]

    res = await scanner.search_cves("openssh", "8.9")
    assert len(res) == 1
    assert res[0]["id"] == "CVE-2023-0001"
    assert res[0]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_scan_no_versions():
    """Test CVE scan with no version info."""
    hosts = [{"ip": "1.1.1.1", "tcp_ports": [{"port": 80, "product": "apache"}]}]
    res = await scanner.scan(hosts)
    assert res.summary["total_services"] == 0
    assert res.summary["skipped_no_version"] == 1


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_scan_with_versions(mock_search):
    mock_search.return_value = [{"id": "CVE-1", "severity": "HIGH", "score": 7.5}]
    hosts = [{"ip": "1.1.1.1", "tcp_ports": [{"port": 80, "product": "apache", "version": "2.4"}]}]
    res = await scanner.scan(hosts)
    assert res.summary["total_services"] == 1
    assert res.summary["total_cves"] == 1


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_search_cves_rate_limit(mock_search_async):
    mock_search_async.return_value = []

    res = await scanner.search_cves("test", "1.0", verbose=True)
    assert res == []
    assert mock_search_async.called


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_search_cves_errors(mock_search_async):
    # Test no product
    assert await scanner.search_cves("") == []

    # Test error case
    mock_search_async.return_value = []
    assert await scanner.search_cves("test", verbose=True) == []


@pytest.mark.asyncio
async def test_search_cves_async_real_calls():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-TEST",
                    "descriptions": [{"lang": "en", "value": "Test desc"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }

    client = AsyncMock()
    client.get.return_value = mock_response

    res = await scanner.search_cves_async(client, "product", "1.0")
    assert len(res) == 1
    assert res[0]["id"] == "CVE-TEST"


@pytest.mark.asyncio
async def test_search_cves_async_rate_limit():
    mock_response_403 = MagicMock()
    mock_response_403.status_code = 403

    mock_response_200 = MagicMock()
    mock_response_200.status_code = 200
    mock_response_200.json.return_value = {"vulnerabilities": []}

    client = AsyncMock()
    client.get.side_effect = [mock_response_403, mock_response_200]

    with patch("asyncio.sleep", new_callable=AsyncMock):
        res = await scanner.search_cves_async(client, "product", "1.0")
        assert res == []
        assert client.get.call_count == 2


@pytest.mark.asyncio
async def test_search_cves_async_error():
    client = AsyncMock()
    client.get.side_effect = Exception("Network error")

    res = await scanner.search_cves_async(client, "product", "1.0")
    assert res == []


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_scan_verbose_and_callback(mock_search):
    mock_search.return_value = [
        {"id": "CVE-1", "severity": "CRITICAL", "score": 9.8, "description": "X" * 300},
        {"id": "CVE-2", "severity": "HIGH", "score": 8.0, "description": "Y"},
    ]
    hosts = [
        {
            "ip": "1.1.1.1",
            "tcp_ports": [
                {"port": 80, "product": "apache", "version": "2.4", "service": "http"},
                {"port": 22, "product": "openssh", "version": "8.9"},
            ],
        }
    ]
    cb = MagicMock()
    res = await scanner.scan(hosts, verbose=True, progress_callback=cb)
    assert res.summary["total_services"] == 2
    assert res.summary["critical_cves"] == 2
    assert res.summary["high_cves"] == 2
    assert cb.called


@pytest.mark.asyncio
async def test_search_cves_async_no_product():
    assert await scanner.search_cves_async(AsyncMock(), "") == []


@pytest.mark.asyncio
async def test_search_cves_async_with_api_key():
    with patch("edgewalker.modules.cve_scan.scanner.settings") as mock_settings:
        mock_settings.nvd_api_key = "test-key"
        mock_settings.nvd_api_url = "http://test"

        client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        client.get.return_value = mock_response

        await scanner.search_cves_async(client, "product")
        args, kwargs = client.get.call_args
        assert kwargs["headers"]["apiKey"] == "test-key"


@pytest.mark.asyncio
async def test_search_cves_async_non_200():
    client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 500
    client.get.return_value = mock_response

    assert await scanner.search_cves_async(client, "product") == []


@pytest.mark.asyncio
async def test_search_cves_async_verbose():
    client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"vulnerabilities": []}
    client.get.return_value = mock_response

    await scanner.search_cves_async(client, "product", verbose=True)
    assert client.get.called


@pytest.mark.asyncio
async def test_scan_hosts_verbose_no_progress():
    hosts = [
        {"ip": "1.1.1.1", "tcp_ports": [{"port": 80, "product": "apache", "version": "2.4"}]},
        {"ip": "1.1.1.2", "tcp_ports": [{"port": 80, "product": "apache"}]},
    ]
    s = scanner.CveScanner(verbose=True)

    with patch(
        "edgewalker.modules.cve_scan.scanner.search_cves_async",
        new_callable=AsyncMock,
        return_value=[],
    ):
        # Mock print to avoid output
        with patch("builtins.print"):
            await s.scan_hosts(hosts)


@pytest.mark.asyncio
async def test_cve_scanner_scan_interface():
    s = scanner.CveScanner()
    with patch.object(s, "scan_hosts", new_callable=AsyncMock) as mock_scan:
        await s.scan(hosts=[{"ip": "1.1.1.1"}])
        mock_scan.assert_called_once()

        await s.scan(hosts=None)
        mock_scan.assert_called_with([])
