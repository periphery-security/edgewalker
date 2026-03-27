"""Tests for Enhanced Discovery Modules."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.discovery.http import discover_http
from edgewalker.modules.discovery.mdns import discover_mdns
from edgewalker.modules.discovery.upnp import discover_upnp


@pytest.mark.asyncio
async def test_mdns_discovery():
    with patch("edgewalker.modules.discovery.mdns.Zeroconf") as mock_zc:
        with patch("edgewalker.modules.discovery.mdns.ServiceBrowser") as mock_browser:
            # Mock discovered devices
            mock_listener = MagicMock()
            mock_listener.discovered_devices = {"192.168.1.50": "SmartTV"}

            with patch(
                "edgewalker.modules.discovery.mdns.MDNSListener", return_value=mock_listener
            ):
                results = await discover_mdns(timeout=0.1)
                assert "192.168.1.50" in results
                assert results["192.168.1.50"] == "SmartTV"


@pytest.mark.asyncio
async def test_upnp_discovery():
    with patch("socket.socket") as mock_socket:
        mock_sock_inst = mock_socket.return_value
        # Mock SSDP response
        mock_sock_inst.recvfrom.return_value = (
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.100:8080/desc.xml\r\nST: upnp:rootdevice\r\n\r\n",
            ("192.168.1.100", 1900),
        )

        with patch("edgewalker.modules.discovery.upnp._fetch_upnp_description") as mock_fetch:
            mock_fetch.return_value = {"modelName": "Hue Bridge", "manufacturer": "Signify"}

            results = await discover_upnp(timeout=0.2)
            assert "192.168.1.100" in results
            assert results["192.168.1.100"]["modelName"] == "Hue Bridge"


@pytest.mark.asyncio
async def test_http_discovery():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html"}
        mock_resp.text = "<html><head><title>Router Admin</title></head><body></body></html>"
        mock_get.return_value = mock_resp

        server, title = await discover_http("192.168.1.1", 80)
        assert server == "nginx/1.18.0"
        assert title == "Router Admin"
