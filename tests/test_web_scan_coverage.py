# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.web_scan.scanner import WebScanner


@pytest.mark.asyncio
async def test_web_scanner_invalid_hosts_type():
    """Test WebScanner.scan with invalid hosts type."""
    scanner = WebScanner()
    result = await scanner.scan(hosts="not a list")
    assert result.results == []
    assert result.summary["total_services"] == 0


@pytest.mark.asyncio
async def test_web_scanner_sensitive_files_exception():
    """Test WebScanner._scan_service sensitive files exception handling."""
    scanner = WebScanner()

    mock_res_basic = MagicMock()
    mock_res_basic.status_code = 200
    mock_res_basic.headers = {}
    mock_res_basic.text = ""

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        # First call succeeds, second (sensitive file) raises exception
        mock_get.side_effect = [mock_res_basic, Exception("Network error")]

        # We only need to test one sensitive file to trigger the exception block
        with patch("edgewalker.modules.web_scan.scanner.SENSITIVE_PATHS", [".env"]):
            result = await scanner._scan_service("1.1.1.1", 80, "http")
            assert result.status_code == 200
            assert result.sensitive_files == []  # Exception was caught and ignored


@pytest.mark.asyncio
async def test_web_scanner_get_tls_info_exception():
    """Test WebScanner._get_tls_info exception handling."""
    scanner = WebScanner()
    with patch("ssl.create_default_context") as mock_ctx:
        mock_ctx.side_effect = Exception("SSL error")
        result = await scanner._get_tls_info("1.1.1.1", 443)
        assert result is None


@pytest.mark.asyncio
async def test_web_scanner_get_tls_info_inner_functions():
    """Test WebScanner._get_tls_info inner functions by NOT mocking to_thread."""
    scanner = WebScanner()

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.getpeercert.side_effect = [
        b"binary_cert",  # First call in _get_cert
        {
            "notAfter": "Jan 01 00:00:00 2030 GMT",
            "issuer": "Test",
        },  # Second call in _get_decoded_cert
    ]
    mock_ssock.cipher.return_value = ("cipher", "TLSv1.3", 256)
    mock_ssock.version.return_value = "TLSv1.3"

    with patch("ssl.create_connection", return_value=mock_sock):
        with patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            # We don't mock asyncio.to_thread here, so it runs the inner functions
            result = await scanner._get_tls_info("1.1.1.1", 443)
            assert result is not None
            assert result.protocol == "TLSv1.3"
            assert result.expired is False
