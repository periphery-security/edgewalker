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
async def test_probe_services_single():
    # First Party
    from edgewalker.modules.port_scan.scanner import _probe_services

    with patch(
        "edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock
    ) as mock_batch:
        mock_batch.return_value = ("xml", {"1.1.1.1"})
        xmls, found = await _probe_services({"1.1.1.1": [80]})
        assert xmls == ["xml"]
        assert found == {"1.1.1.1"}


@pytest.mark.asyncio
async def test_probe_services_multiple():
    # First Party
    from edgewalker.modules.port_scan.scanner import _probe_services

    with patch(
        "edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock
    ) as mock_batch:
        mock_batch.side_effect = [("xml1", {"1.1.1.1"}), ("xml2", {"2.2.2.2"})]
        xmls, found = await _probe_services({"1.1.1.1": [80], "2.2.2.2": [443]})
        assert len(xmls) == 2
        assert found == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.asyncio
async def test_probe_services_exception():
    # First Party
    from edgewalker.modules.port_scan.scanner import _probe_services

    with patch(
        "edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock
    ) as mock_batch:
        mock_batch.side_effect = [Exception("error"), ("xml2", {"2.2.2.2"})]
        xmls, found = await _probe_services({"1.1.1.1": [80], "2.2.2.2": [443]})
        assert xmls == ["xml2"]
        assert found == {"2.2.2.2"}
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


def test_fix_nmap_permissions():
    with patch("sys.platform", "linux"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            # First Party
            from edgewalker.modules.port_scan.scanner import fix_nmap_permissions

            assert fix_nmap_permissions() is True
            assert mock_run.called

    with patch("sys.platform", "darwin"):
        assert fix_nmap_permissions() is False


@pytest.mark.asyncio
async def test_scan_batch_success(tmp_path):
    # Standard Library
    # First Party
    from edgewalker.modules.port_scan.scanner import _scan_batch

    mock_process = AsyncMock()
    mock_process.stdout.readline.side_effect = [
        b"Discovered open port 80/tcp on 1.1.1.1\n",
        b"About 50.00% done\n",
        b"",
    ]
    mock_process.wait.return_value = 0
    mock_process.returncode = 0

    xml_path = tmp_path / "test.xml"
    xml_path.write_text("<nmaprun></nmaprun>")

    with patch("asyncio.create_subprocess_exec", return_value=mock_process):
        with patch("edgewalker.modules.port_scan.scanner.tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.name = str(xml_path)

            xml, hosts = await _scan_batch(["1.1.1.1"], ports="80", extra_flags=[], timeout=60)
            assert "1.1.1.1" in hosts
            assert xml == "<nmaprun></nmaprun>"


@pytest.mark.asyncio
async def test_scan_batch_timeout(tmp_path):
    # Standard Library
    import asyncio

    # First Party
    from edgewalker.modules.port_scan.scanner import _scan_batch

    mock_process = AsyncMock()
    mock_process.stdout.readline.side_effect = asyncio.TimeoutError()
    mock_process.wait.return_value = 0

    xml_path = tmp_path / "test.xml"
    xml_path.write_text("<nmaprun></nmaprun>")

    with patch("asyncio.create_subprocess_exec", return_value=mock_process):
        with patch("edgewalker.modules.port_scan.scanner.tempfile.NamedTemporaryFile") as mock_temp:
            mock_temp.return_value.name = str(xml_path)

            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                xml, hosts = await _scan_batch(["1.1.1.1"], ports="80", extra_flags=[], timeout=1)
                assert mock_process.terminate.called


@pytest.mark.asyncio
async def test_ping_sweep_success():
    # First Party
    from edgewalker.modules.port_scan.scanner import ping_sweep

    mock_process = AsyncMock()
    mock_process.stdout.readline.side_effect = [
        b"Nmap scan report for 1.1.1.1\n",
        b"Nmap scan report for test.local (2.2.2.2)\n",
        b"",
    ]
    mock_process.wait.return_value = 0

    with patch("asyncio.create_subprocess_exec", return_value=mock_process):
        with patch(
            "edgewalker.modules.port_scan.scanner.check_nmap_permissions", return_value=True
        ):
            hosts = await ping_sweep("1.1.1.0/24")
            assert hosts == ["1.1.1.1", "2.2.2.2"]


@pytest.mark.asyncio
async def test_ping_sweep_error():
    # First Party
    from edgewalker.modules.port_scan.scanner import ping_sweep

    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
        hosts = await ping_sweep("1.1.1.0/24")
        assert hosts == []


@pytest.mark.asyncio
async def test_port_scanner_full_with_discovery():
    scanner = PortScanner(target="127.0.0.1")

    with patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None):
        with patch(
            "edgewalker.modules.port_scan.scanner.ping_sweep",
            new_callable=AsyncMock,
            return_value=["127.0.0.1"],
        ):
            with patch(
                "edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock
            ) as mock_parallel:
                xml = "<nmaprun><host><status state='up'/><address addr='127.0.0.1' addrtype='ipv4'/><ports><port portid='80' protocol='tcp'><state state='open'/></port></ports></host></nmaprun>"
                mock_parallel.return_value = ([xml], {"127.0.0.1"})

                with patch(
                    "edgewalker.modules.port_scan.scanner._probe_services", new_callable=AsyncMock
                ) as mock_probe:
                    mock_probe.return_value = ([xml], {"127.0.0.1"})
                    with patch(
                        "edgewalker.modules.port_scan.scanner.discover_mdns",
                        new_callable=AsyncMock,
                        return_value={"127.0.0.1": "test.local"},
                    ):
                        with patch(
                            "edgewalker.modules.port_scan.scanner.discover_upnp",
                            new_callable=AsyncMock,
                            return_value={"127.0.0.1": {"name": "UPnP"}},
                        ):
                            with patch(
                                "edgewalker.modules.port_scan.scanner.discover_http",
                                new_callable=AsyncMock,
                                return_value=("Apache", "HTTP"),
                            ):
                                results = await scanner.full_scan()
                                assert results.success is True
                                assert len(results.hosts) > 0
                                assert results.hosts[0].mdns_name == "test.local"
                                assert results.hosts[0].upnp_info == {"name": "UPnP"}
                                assert results.hosts[0].http_title == "HTTP"
