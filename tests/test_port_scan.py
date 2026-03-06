# Standard Library
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.port_scan import scanner


def test_get_local_ip():
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.return_value.getsockname.return_value = ["192.168.1.50"]
        assert scanner.get_local_ip() == "192.168.1.50"

        mock_sock.return_value.__enter__.return_value.connect.side_effect = Exception("Fail")
        assert scanner.get_local_ip() == "192.168.1.1"


def test_get_default_target():
    with patch("edgewalker.modules.port_scan.scanner.get_local_ip", return_value="192.168.1.50"):
        assert scanner.get_default_target() == "192.168.1.0/24"


def test_chunk_hosts():
    hosts = ["1", "2", "3", "4", "5"]
    assert scanner._chunk_hosts(hosts, 2) == [["1", "2", "3"], ["4", "5"]]
    assert scanner._chunk_hosts(hosts, 5) == [["1"], ["2"], ["3"], ["4"], ["5"]]
    assert scanner._chunk_hosts(hosts, 0) == [hosts]
    assert scanner._chunk_hosts([], 2) == []


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
@patch("tempfile.NamedTemporaryFile")
@patch("builtins.open", new_callable=mock_open, read_data="<nmaprun></nmaprun>")
@patch("os.unlink")
async def test_scan_batch(mock_unlink, mock_file, mock_temp, mock_exec):
    mock_temp.return_value.name = "test.xml"
    mock_proc = AsyncMock()
    mock_proc.stdout.readline.side_effect = [
        b"Discovered open port 80/tcp on 1.1.1.1",
        b"10% done",
        b"",
    ]
    mock_proc.wait.return_value = 0
    mock_proc.returncode = 0
    mock_exec.return_value = mock_proc

    xml, found = await scanner._scan_batch(["1.1.1.1"], "80", [], 10)
    assert xml == "<nmaprun></nmaprun>"
    assert "1.1.1.1" in found


def test_parse_nmap_xml_extended():
    xml = """<nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <hostnames><hostname name="test-host"/></hostnames>
            <os><osmatch name="Linux" accuracy="100"/></os>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache" version="2.4"/>
                </port>
            </ports>
        </host>
        <host><status state="down"/></host>
    </nmaprun>"""
    hosts = scanner.parse_nmap_xml(xml)
    assert len(hosts) == 1
    assert hosts[0].hostname == "test-host"
    assert hosts[0].os[0] == "Linux"
    assert hosts[0].tcp[0].product_name == "Apache"

    assert scanner.parse_nmap_xml("invalid xml") == []


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock)
async def test_parallel_scan(mock_batch):
    mock_batch.return_value = ("xml", {"1.1.1.1"})

    # Single host
    xmls, found = await scanner._parallel_scan(["1.1.1.1"], "80", [], 10)
    assert len(xmls) == 1
    assert "1.1.1.1" in found

    # Multiple hosts
    xmls, found = await scanner._parallel_scan(["1.1.1.1", "1.1.1.2"], "80", [], 10)
    assert len(xmls) >= 1
    assert "1.1.1.1" in found


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_scan_quick(mock_sudo, mock_parallel, mock_ping):
    mock_parallel.return_value = (["<nmaprun></nmaprun>"], {"1.1.1.1"})
    res = await scanner.scan(target="1.1.1.1", full=False)
    assert res.success is True
    assert res.scan_type == "quick"


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner._probe_services", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_scan_full(mock_sudo, mock_probe, mock_parallel, mock_ping):
    # Phase 2 discovery
    mock_parallel.return_value = (
        [
            """<nmaprun><host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>"""
        ],
        {"1.1.1.1"},
    )
    # Phase 3 probe
    mock_probe.return_value = (["<nmaprun></nmaprun>"], {"1.1.1.1"})

    res = await scanner.scan(target="1.1.1.1", full=True)
    assert res.success is True
    assert res.scan_type == "full"


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
async def test_ping_sweep_extended(mock_exec):
    mock_proc = AsyncMock()
    mock_proc.stdout.readline.side_effect = [
        b"Nmap scan report for 1.1.1.1",
        b"Nmap scan report for 1.1.1.2",
        b"",
    ]
    mock_proc.wait.return_value = 0
    mock_exec.return_value = mock_proc

    res = await scanner.ping_sweep("1.1.1.0/24", verbose=True)
    assert len(res) == 2
    assert "1.1.1.1" in res


@pytest.mark.asyncio
async def test_ping_sweep_invalid_target():
    """Verify that ping_sweep raises ValueError for invalid targets."""
    with pytest.raises(ValueError, match="Invalid target"):
        await scanner.ping_sweep("-iL /etc/passwd")

    with pytest.raises(ValueError, match="Target cannot be empty"):
        await scanner.ping_sweep(" ")


def test_validate_target():
    assert scanner.validate_target("1.1.1.1") is None
    assert scanner.validate_target("1.1.1.0/24") is None
    assert scanner.validate_target("google.com") is None
    assert scanner.validate_target("") == "Target cannot be empty"
    assert (
        scanner.validate_target("-v") == "Invalid target: -v (targets cannot start with a hyphen)"
    )
    assert scanner.validate_target("1.1.1.256") is not None


def test_check_privileges():
    with patch("os.geteuid", return_value=0):
        assert scanner.check_privileges() is None

    with patch("os.geteuid", return_value=1000):
        with patch("sys.platform", "darwin"):
            assert scanner.check_privileges() is not None

        with patch("sys.platform", "linux"):
            with patch("subprocess.check_output") as mock_out:
                mock_out.side_effect = [
                    "/usr/bin/nmap",
                    "Capabilities for nmap: cap_net_raw,cap_net_admin+ep",
                ]
                assert scanner.check_privileges() is None


def test_get_nmap_command():
    with patch("os.geteuid", return_value=0):
        assert scanner.get_nmap_command() == ["nmap"]

    with patch("os.geteuid", return_value=1000):
        with patch("sys.platform", "darwin"):
            assert scanner.get_nmap_command() == ["sudo", "nmap"]

        with patch("sys.platform", "linux"):
            with patch("subprocess.check_output") as mock_out:
                mock_out.side_effect = [
                    "/usr/bin/nmap",
                    "Capabilities for nmap: cap_net_raw,cap_net_admin+ep",
                ]
                assert scanner.get_nmap_command() == ["nmap"]


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
@patch("tempfile.NamedTemporaryFile")
@patch("builtins.open", new_callable=mock_open, read_data="<nmaprun></nmaprun>")
@patch("os.unlink")
async def test_scan_batch_verbose_callback(mock_unlink, mock_file, mock_temp, mock_exec):
    mock_temp.return_value.name = "test.xml"
    mock_proc = AsyncMock()
    mock_proc.stdout.readline.side_effect = [
        b"Discovered open port 80/tcp on 1.1.1.1",
        b"10% done",
        b"",
    ]
    mock_proc.wait.return_value = 0
    mock_proc.returncode = 0
    mock_exec.return_value = mock_proc

    cb = MagicMock()
    with patch("builtins.print"):
        xml, found = await scanner._scan_batch(
            ["1.1.1.1"], "80", [], 10, verbose=True, progress_callback=cb
        )
    assert "1.1.1.1" in found
    assert cb.called


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock)
async def test_parallel_scan_verbose(mock_batch):
    mock_batch.return_value = ("xml", {"1.1.1.1"})
    with patch("builtins.print"):
        await scanner._parallel_scan(["1.1.1.1", "1.1.1.2"], "80", [], 10, verbose=True)


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock)
async def test_probe_services_verbose(mock_batch):
    mock_batch.return_value = ("xml", {"1.1.1.1"})
    with patch("builtins.print"):
        await scanner._probe_services({"1.1.1.1": [80], "1.1.1.2": [443]}, verbose=True)


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_scan_quick_verbose_callback(mock_sudo, mock_parallel, mock_ping):
    mock_parallel.return_value = (["<nmaprun></nmaprun>"], {"1.1.1.1"})
    cb = MagicMock()
    with patch("builtins.print"):
        res = await scanner.scan(target="1.1.1.1", full=False, verbose=True, progress_callback=cb)
    assert res.success is True
    assert cb.called


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner._probe_services", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_scan_full_verbose_callback(mock_sudo, mock_probe, mock_parallel, mock_ping):
    mock_parallel.return_value = (
        [
            """<nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/><ports><port portid="80" protocol="tcp"><state state="open"/></port></ports></host></nmaprun>"""
        ],
        {"1.1.1.1"},
    )
    mock_probe.return_value = (["<nmaprun></nmaprun>"], {"1.1.1.1"})
    cb = MagicMock()
    with patch("builtins.print"):
        res = await scanner.scan(target="1.1.1.1", full=True, verbose=True, progress_callback=cb)
    assert res.success is True
    assert cb.called


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", side_effect=FileNotFoundError)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_scan_quick_nmap_not_found(mock_sudo, mock_parallel, mock_ping):
    res = await scanner.scan(target="1.1.1.1", full=False)
    assert res.success is False
    assert "nmap not found" in res.error


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock)
async def test_probe_services(mock_batch):
    mock_batch.return_value = ("xml", {"1.1.1.1"})
    res_xml, res_found = await scanner._probe_services({"1.1.1.1": [80, 443]})
    assert len(res_xml) == 1
    assert "1.1.1.1" in res_found


# --- Unprivileged mode tests ---


def test_check_privileges_unprivileged_mode():
    """check_privileges returns None immediately when unprivileged=True."""
    # Even without root, unprivileged mode skips the check
    with patch("os.geteuid", return_value=1000):
        with patch("sys.platform", "darwin"):
            assert scanner.check_privileges(unprivileged=True) is None


def test_get_nmap_command_unprivileged():
    """get_nmap_command returns ['nmap'] when unprivileged=True, even without root."""
    with patch("os.geteuid", return_value=1000):
        with patch("sys.platform", "darwin"):
            assert scanner.get_nmap_command(unprivileged=True) == ["nmap"]


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
@patch("tempfile.NamedTemporaryFile")
@patch("builtins.open", new_callable=mock_open, read_data="<nmaprun></nmaprun>")
@patch("os.unlink")
async def test_scan_batch_adds_unprivileged_flag(mock_unlink, mock_file, mock_temp, mock_exec):
    """_scan_batch prepends --unprivileged to the nmap command when unprivileged=True."""
    mock_temp.return_value.name = "test.xml"
    mock_proc = AsyncMock()
    mock_proc.stdout.readline.side_effect = [b""]
    mock_proc.wait.return_value = 0
    mock_proc.returncode = 0
    mock_exec.return_value = mock_proc

    with patch("os.geteuid", return_value=1000), patch("sys.platform", "darwin"):
        await scanner._scan_batch(["1.1.1.1"], "80", [], 10, unprivileged=True)

    call_args = mock_exec.call_args[0]
    assert "--unprivileged" in call_args


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
async def test_ping_sweep_unprivileged(mock_exec):
    """ping_sweep passes --unprivileged flag to nmap when unprivileged=True."""
    mock_proc = AsyncMock()
    mock_proc.stdout.readline.side_effect = [b"Nmap scan report for 1.1.1.1", b""]
    mock_proc.wait.return_value = 0
    mock_exec.return_value = mock_proc

    with patch("os.geteuid", return_value=1000), patch("sys.platform", "darwin"):
        res = await scanner.ping_sweep("1.1.1.0/24", unprivileged=True)

    call_args = mock_exec.call_args[0]
    assert "--unprivileged" in call_args
    assert "1.1.1.1" in res


def test_port_scanner_stores_unprivileged():
    """PortScanner stores the unprivileged flag."""
    ps = scanner.PortScanner(unprivileged=True)
    assert ps.unprivileged is True

    ps_default = scanner.PortScanner()
    assert ps_default.unprivileged is False


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner.ping_sweep", new_callable=AsyncMock, return_value=[])
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
async def test_quick_scan_unprivileged_skips_permission_check(mock_parallel, mock_ping):
    """quick_scan with unprivileged=True does not raise PermissionError."""
    mock_parallel.return_value = ([], set())
    # On macOS without root, normal mode would raise PermissionError
    with patch("os.geteuid", return_value=1000), patch("sys.platform", "darwin"):
        ps = scanner.PortScanner(target="1.1.1.0/24", unprivileged=True)
        result = await ps.quick_scan()
    assert result.success is True
