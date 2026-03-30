# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.port_scan.scanner import (
    PortScanner,
    check_privileges,
    detect_gateway,
    get_default_target,
    get_local_ip,
    get_nmap_command,
    parse_nmap_xml,
    ping_sweep,
    validate_target,
)


def test_port_scan_utils():
    assert get_local_ip() is not None
    assert "/" in get_default_target()
    assert validate_target("127.0.0.1") is None
    assert validate_target("-invalid") is not None
    assert validate_target("192.168.1.0/24") is None


def test_detect_gateway():
    with patch("sys.platform", "darwin"):
        with patch("subprocess.check_output", return_value="default 192.168.1.1 UGSc 0 0 en0"):
            assert detect_gateway() == "192.168.1.1"

    with patch("sys.platform", "linux"):
        with patch("subprocess.check_output", return_value="default via 192.168.1.254 dev eth0"):
            assert detect_gateway() == "192.168.1.254"

    with patch("subprocess.check_output", side_effect=Exception("error")):
        with patch(
            "edgewalker.modules.port_scan.scanner.get_local_ip", return_value="192.168.1.50"
        ):
            assert detect_gateway() == "192.168.1.1"


def test_port_scan_privileges():
    with patch("os.geteuid", return_value=0):
        assert check_privileges() is None
        assert get_nmap_command() == ["nmap"]

    with patch("os.geteuid", return_value=1000):
        with patch("sys.platform", "darwin"):
            assert check_privileges() is not None
            assert get_nmap_command() == ["sudo", "nmap"]


def test_parse_nmap_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4"/></port></ports></host>
</nmaprun>
"""
    hosts = parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert str(hosts[0].ip) == "127.0.0.1"
    assert hosts[0].tcp[0].port == 80


@pytest.mark.asyncio
async def test_ping_sweep():
    mock_process = MagicMock()
    mock_process.stdout.readline = AsyncMock(side_effect=[b"Nmap scan report for 127.0.0.1\n", b""])
    mock_process.wait = AsyncMock(return_value=0)

    with patch("asyncio.create_subprocess_exec", return_value=mock_process):
        hosts = await ping_sweep("127.0.0.1")
        assert hosts == ["127.0.0.1"]


@pytest.mark.asyncio
async def test_port_scanner_quick():
    scanner = PortScanner(target="127.0.0.1")

    with patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None):
        with patch(
            "edgewalker.modules.port_scan.scanner.ping_sweep", new_callable=AsyncMock
        ) as mock_ping:
            mock_ping.return_value = ["127.0.0.1"]
            with patch(
                "edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock
            ) as mock_parallel:
                mock_parallel.return_value = (["<nmaprun></nmaprun>"], {"127.0.0.1"})
                results = await scanner.quick_scan()
                assert results.success is True
                assert results.target == "127.0.0.1"
