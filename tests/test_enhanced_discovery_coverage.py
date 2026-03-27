"""Comprehensive tests for Enhanced Discovery features and their integration."""

# Standard Library
import socket
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.core.config import Settings
from edgewalker.core.risk import RiskEngine
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.discovery.http import discover_http
from edgewalker.modules.discovery.mdns import MDNSListener, discover_mdns
from edgewalker.modules.discovery.upnp import _fetch_upnp_description, discover_upnp
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort


@pytest.mark.asyncio
async def test_mdns_listener_add_service():
    listener = MDNSListener()
    mock_zc = MagicMock()
    mock_info = MagicMock()
    mock_info.addresses = [socket.inet_aton("192.168.1.50")]
    mock_info.server = "test-device.local."
    mock_zc.get_service_info.return_value = mock_info

    listener.add_service(mock_zc, "_http._tcp.local.", "Test Service._http._tcp.local.")
    assert listener.discovered_devices["192.168.1.50"] == "test-device"


@pytest.mark.asyncio
async def test_mdns_discovery_timeout():
    with (
        patch("edgewalker.modules.discovery.mdns.Zeroconf"),
        patch("edgewalker.modules.discovery.mdns.ServiceBrowser"),
    ):
        results = await discover_mdns(timeout=0.1)
        assert isinstance(results, dict)


@pytest.mark.asyncio
async def test_upnp_fetch_description_fail():
    with patch("httpx.AsyncClient.get", side_effect=Exception("Network error")):
        result = await _fetch_upnp_description("http://192.168.1.1/desc.xml")
        assert result is None


@pytest.mark.asyncio
async def test_http_discovery_no_title():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "test-server", "Content-Type": "text/plain"}
        mock_resp.text = "no title here"
        mock_get.return_value = mock_resp

        server, title = await discover_http("192.168.1.1", 80)
        assert server == "test-server"
        assert title is None


def test_telemetry_anonymization_new_fields():
    settings = Settings()
    tm = TelemetryManager(settings)

    raw_data = {
        "device_id": "test-id",
        "hosts": [
            {
                "ip": "192.168.1.100",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "Johns-iPhone",
                "mdns_name": "Johns-iPhone",
                "upnp_info": {
                    "friendlyName": "John's Living Room TV",
                    "manufacturer": "Samsung",
                    "modelName": "QLED 4K",
                    "serialNumber": "123456789",
                },
                "http_title": "Login Page for John",
            }
        ],
    }

    anon_data = tm.anonymize_scan_data(raw_data)
    host = anon_data["hosts"][0]

    assert host["hostname"] == ""
    assert host["mdns_name"] == "redacted"
    assert host["upnp_info"]["friendlyName"] == "redacted"
    assert host["upnp_info"]["serialNumber"] == "redacted"
    assert host["upnp_info"]["manufacturer"] == "Samsung"
    assert host["http_title"] == "redacted"


def test_risk_engine_discovery_data():
    host = Host(
        ip="192.168.1.100",
        mac="AA:BB:CC:DD:EE:FF",
        vendor="Apple",
        mdns_name="My-Apple-TV",
        upnp_info={"modelName": "Apple TV 4K"},
        http_server="Apple-Server",
        http_title="Home",
    )
    port_model = PortScanModel(hosts=[host], target="192.168.1.0/24")
    cred_model = PasswordScanModel(results=[])
    cve_model = CveScanModel(results=[])

    engine = RiskEngine(port_model, cred_model, cve_model)
    risk = engine.calculate_device_risk("192.168.1.100")

    assert risk["mdns_name"] == "My-Apple-TV"
    assert risk["upnp_info"]["modelName"] == "Apple TV 4K"
    assert risk["http_server"] == "Apple-Server"
    assert risk["http_title"] == "Home"


@pytest.mark.asyncio
async def test_mdns_listener_add_service_no_info():
    listener = MDNSListener()
    mock_zc = MagicMock()
    mock_zc.get_service_info.return_value = None

    listener.add_service(mock_zc, "_http._tcp.local.", "Test Service._http._tcp.local.")
    assert len(listener.discovered_devices) == 0


@pytest.mark.asyncio
async def test_mdns_discovery_exception():
    with patch("edgewalker.modules.discovery.mdns.Zeroconf") as mock_zc:
        mock_zc.side_effect = Exception("ZC Error")
        # The exception is caught inside discover_mdns
        results = await discover_mdns(timeout=0.1)
        assert results == {}


@pytest.mark.asyncio
async def test_upnp_discovery_socket_error():
    with patch("socket.socket") as mock_sock:
        mock_sock.side_effect = Exception("Socket Error")
        # The exception is caught inside discover_upnp
        results = await discover_upnp(timeout=0.1)
        assert results == {}


@pytest.mark.asyncio
async def test_upnp_fetch_description_bad_status():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        result = await _fetch_upnp_description("http://192.168.1.1/desc.xml")
        assert result is None


@pytest.mark.asyncio
async def test_http_discovery_exception():
    with patch("httpx.AsyncClient.get", side_effect=Exception("HTTP Error")):
        server, title = await discover_http("192.168.1.1", 80)
        assert server is None
        assert title is None


def test_telemetry_anonymization_missing_fields():
    settings = Settings()
    tm = TelemetryManager(settings)

    raw_data = {
        "device_id": "test-id",
        "hosts": [{"ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:FF"}],
    }

    anon_data = tm.anonymize_scan_data(raw_data)
    host = anon_data["hosts"][0]
    assert "mdns_name" not in host


def test_risk_engine_discovery_data_missing():
    host = Host(ip="192.168.1.100", mac="AA:BB:CC:DD:EE:FF", vendor="Apple")
    port_model = PortScanModel(hosts=[host], target="192.168.1.0/24")
    cred_model = PasswordScanModel(results=[])
    cve_model = CveScanModel(results=[])

    engine = RiskEngine(port_model, cred_model, cve_model)
    risk = engine.calculate_device_risk("192.168.1.100")

    assert risk["mdns_name"] is None
    assert risk["upnp_info"] is None


@pytest.mark.asyncio
async def test_port_scanner_integration():
    # First Party
    from edgewalker.modules.port_scan.scanner import PortScanner

    with (
        patch("edgewalker.modules.port_scan.scanner.ping_sweep", return_value=["192.168.1.100"]),
        patch(
            "edgewalker.modules.port_scan.scanner.discover_mdns",
            return_value={"192.168.1.100": "Test-Device"},
        ),
        patch(
            "edgewalker.modules.port_scan.scanner.discover_upnp",
            return_value={"192.168.1.100": {"modelName": "Test-Model"}},
        ),
        patch(
            "edgewalker.modules.port_scan.scanner._parallel_scan",
            return_value=(["<xml></xml>"], {"192.168.1.100"}),
        ),
        patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None),
        patch("edgewalker.modules.port_scan.scanner.parse_nmap_xml") as mock_parse,
    ):
        mock_host = Host(
            ip="192.168.1.100", mac="00:11:22:33:44:55", tcp=[TcpPort(port=80, name="http")]
        )
        mock_parse.return_value = [mock_host]

        with patch(
            "edgewalker.modules.port_scan.scanner.discover_http", return_value=("Server1", "Title1")
        ):
            scanner = PortScanner(target="192.168.1.100")
            results = await scanner.quick_scan()

            assert len(results.hosts) == 1
            host = results.hosts[0]
            assert host.mdns_name == "Test-Device"
            assert host.upnp_info["modelName"] == "Test-Model"
            assert host.http_server == "Server1"
            assert host.http_title == "Title1"
