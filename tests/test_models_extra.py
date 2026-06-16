# First Party
from edgewalker.core.models import Base
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort


def test_tcp_port_model():
    p = TcpPort(port=80, name="http", product_name="Apache", product_version="2.4")
    assert p["service"] == "http"
    assert p["product"] == "Apache"
    assert p["version"] == "2.4"
    assert p.get("service") == "http"


def test_host_model():
    h = Host(ip="127.0.0.1", mac="00:11:22:33:44:55", tcp=[TcpPort(port=80, name="http")])
    assert h["tcp_ports"] == h.tcp
    assert h.get("tcp_ports") == h.tcp
    assert h["os_matches"] == []


def test_port_scan_model():
    host = Host(ip="127.0.0.1", mac="00:11:22:33:44:55")
    ps = PortScanModel(hosts=[host])
    assert ps.hosts == [host]


def test_base_model():
    b = Base(module="test")
    assert b.module == "test"
