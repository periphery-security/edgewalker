# Third Party
import pytest
from pydantic import IPvAnyAddress

# First Party
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort, UdpPort


def test_udp_port_model():
    port = UdpPort(port=53, name="dns", product_name="bind", product_version="9.16")
    assert port["port"] == 53
    assert port["service"] == "dns"
    assert port["product"] == "bind"
    assert port["version"] == "9.16"
    assert port.get("port") == 53
    assert port.get("service") == "dns"
    assert port.get("product") == "bind"
    assert port.get("version") == "9.16"
    assert port.get("nonexistent", "default") == "default"
    assert port.get(123, "default") == "default"

    with pytest.raises(TypeError):
        port[123]
    with pytest.raises(KeyError):
        port["nonexistent"]


def test_tcp_port_model():
    port = TcpPort(port=80, name="http", product_name="nginx", product_version="1.18")
    assert port["port"] == 80
    assert port["service"] == "http"
    assert port["product"] == "nginx"
    assert port["version"] == "1.18"
    assert port.get("port") == 80
    assert port.get("service") == "http"
    assert port.get("product") == "nginx"
    assert port.get("version") == "1.18"
    assert port.get("nonexistent", "default") == "default"
    assert port.get(123, "default") == "default"

    with pytest.raises(TypeError):
        port[123]
    with pytest.raises(KeyError):
        port["nonexistent"]


def test_host_model():
    tcp_port = TcpPort(port=80, name="http")
    udp_port = UdpPort(port=53, name="dns")
    host = Host(
        ip="192.168.1.1",
        mac="00:11:22:33:44:55",
        hostname="router",
        vendor="TP-Link",
        tcp=[tcp_port],
        udp=[udp_port],
        os=["Linux 5.0"],
    )

    assert host["ip"] == IPvAnyAddress("192.168.1.1")
    assert host["tcp_ports"] == [tcp_port]
    assert host["udp_ports"] == [udp_port]
    assert host["os_matches"] == [{"name": "Linux 5.0"}]
    assert host.get("tcp_ports") == [tcp_port]
    assert host.get("udp_ports") == [udp_port]
    assert host.get("nonexistent", "default") == "default"
    assert host.get(123, "default") == "default"

    with pytest.raises(TypeError):
        host[123]
    with pytest.raises(KeyError):
        host["nonexistent"]


def test_host_serialization():
    host = Host(ip="192.168.1.1", mac="00:11:22:33:44:55")

    # Default serialization
    data = host.model_dump(mode="json")
    assert data["ip"] == "192.168.1.1"
    assert data["mac"] == "00:11:22:33:44:55"

    # Public mode serialization
    data_public = host.model_dump(mode="json", context={"mode": "public"})
    assert data_public["ip"] == "0.0.1.1"
    assert data_public["mac"] == "00:11:22:00:00:00"

    # IPv6 Public mode serialization
    host_v6 = Host(ip="2001:db8::1", mac="00:11:22:33:44:55")
    data_v6_public = host_v6.model_dump(mode="json", context={"mode": "public"})
    assert data_v6_public["ip"] == "0000:0000:0000:0000:0000:0000:0000:0001"


def test_port_scan_model():
    model = PortScanModel(target="192.168.1.0/24")
    assert model["target"] == "192.168.1.0/24"
    assert model.get("target") == "192.168.1.0/24"
    assert model.get("nonexistent", "default") == "default"

    with pytest.raises(TypeError):
        model[123]
    with pytest.raises(KeyError):
        model["nonexistent"]
