# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.web_scan.scanner import WebScanner


@pytest.mark.asyncio
async def test_web_scanner_discovery():
    # First Party
    from edgewalker.modules.web_scan.models import WebScanResultModel

    scanner = WebScanner()
    hosts = [
        {
            "ip": "1.1.1.1",
            "tcp_ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
        },
        {
            "ip": "2.2.2.2",
            "tcp": [{"port": 8080, "name": "http-alt"}],
        },
    ]

    with patch.object(scanner, "_scan_service", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = WebScanResultModel(ip="1.1.1.1", port=80, protocol="http")
        await scanner.scan(hosts=hosts)
        assert mock_scan.call_count == 3


@pytest.mark.asyncio
async def test_web_scanner_scan_service_basic():
    scanner = WebScanner()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {
        "Server": "Apache",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }
    mock_response.text = "<html><head><title>Test Title</title></head><body></body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        result = await scanner._scan_service("1.1.1.1", 80, "http")

        assert result.status_code == 200
        assert result.server == "Apache"
        assert result.title == "Test Title"
        assert result.headers.csp is True
        assert result.headers.hsts is True


@pytest.mark.asyncio
async def test_web_scanner_sensitive_files():
    scanner = WebScanner()

    def mock_get_side_effect(url, **kwargs):
        mock_res = MagicMock()
        if ".env" in url:
            mock_res.status_code = 200
        else:
            mock_res.status_code = 404
        return mock_res

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = mock_get_side_effect

        # Mock the first call (basic info) to return a normal response
        mock_res_basic = MagicMock()
        mock_res_basic.status_code = 200
        mock_res_basic.headers = {}
        mock_res_basic.text = ""

        # We need to handle the multiple calls to get()
        # 1 for basic info, N for SENSITIVE_PATHS
        mock_get.side_effect = [mock_res_basic] + [
            mock_get_side_effect(f"http://1.1.1.1:80/{p}")
            for p in [
                ".env",
                ".git/config",
                "phpinfo.php",
                "backup.sql",
                "config.php.bak",
                "wp-config.php",
                ".htaccess",
                "server-status",
            ]
        ]

        result = await scanner._scan_service("1.1.1.1", 80, "http")
        assert ".env" in result.sensitive_files


@pytest.mark.asyncio
async def test_web_scanner_tls_info():
    scanner = WebScanner()

    mock_tls_info = MagicMock()
    mock_tls_info.expired = False

    with patch.object(scanner, "_get_tls_info", new_callable=AsyncMock) as mock_tls:
        mock_tls.return_value = mock_tls_info

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(status_code=200, headers={}, text="")

            result = await scanner._scan_service("1.1.1.1", 443, "https")
            assert result.tls is not None
            assert result.tls.expired is False


@pytest.mark.asyncio
async def test_web_scanner_get_tls_info_success():
    scanner = WebScanner()

    mock_cert = {
        "notAfter": "Jan 01 00:00:00 2030 GMT",
        "issuer": "Test Issuer",
    }

    with patch("ssl.create_default_context"):
        with patch("ssl.create_connection"):
            with patch("asyncio.to_thread") as mock_thread:
                # First call for _get_cert, second for _get_decoded_cert
                mock_thread.side_effect = [
                    (b"cert", ("cipher", "TLSv1.3", 256), "TLSv1.3"),
                    mock_cert,
                ]

                result = await scanner._get_tls_info("1.1.1.1", 443)
                assert result.protocol == "TLSv1.3"
                assert result.issuer == "Test Issuer"
                assert result.expired is False


@pytest.mark.asyncio
async def test_web_scanner_get_tls_info_expired():
    scanner = WebScanner()

    mock_cert = {
        "notAfter": "Jan 01 00:00:00 2020 GMT",
        "issuer": "Test Issuer",
    }

    with patch("ssl.create_default_context"):
        with patch("ssl.create_connection"):
            with patch("asyncio.to_thread") as mock_thread:
                mock_thread.side_effect = [
                    (b"cert", ("cipher", "TLSv1.3", 256), "TLSv1.3"),
                    mock_cert,
                ]

                result = await scanner._get_tls_info("1.1.1.1", 443)
                assert result.expired is True


@pytest.mark.asyncio
async def test_web_scanner_scan_error():
    scanner = WebScanner()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Connection error")

        result = await scanner._scan_service("1.1.1.1", 80, "http")
        assert "Connection error" in result.error
