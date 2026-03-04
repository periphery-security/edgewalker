# Standard Library
import asyncio
import io
import sys
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.password_scan import scanner


def test_check_port_open():
    """Test port open check."""
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.return_value.connect_ex.return_value = 0
        assert scanner.check_port_open("1.1.1.1", 80) is True

        mock_sock.return_value.__enter__.return_value.connect_ex.return_value = 1
        assert scanner.check_port_open("1.1.1.1", 80) is False


def test_check_port_open_exception():
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.side_effect = Exception("Socket error")
        assert scanner.check_port_open("1.1.1.1", 80) is False


@pytest.mark.asyncio
@patch("asyncssh.connect")
async def test_test_ssh_success(mock_ssh):
    """Test successful SSH login."""
    # Mock async context manager
    mock_ssh.return_value.__aenter__.return_value = MagicMock()
    assert await scanner.test_ssh("host", 22, "user", "pass") is True


@pytest.mark.asyncio
@patch("asyncssh.connect")
async def test_test_ssh_failure(mock_ssh):
    """Test failed SSH login."""
    mock_ssh.side_effect = Exception("Fail")
    assert await scanner.test_ssh("host", 22, "user", "wrong") is False


@pytest.mark.asyncio
@patch("ftplib.FTP")
async def test_test_ftp(mock_ftp):
    mock_ftp.return_value.__enter__.return_value.login.return_value = "OK"
    assert await scanner.test_ftp("host", 21, "user", "pass") is True

    mock_ftp.return_value.__enter__.return_value.login.side_effect = Exception("Fail")
    assert await scanner.test_ftp("host", 21, "user", "wrong") is False


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.password_scan.scanner.TelnetScanner.attempt_login", new_callable=AsyncMock
)
async def test_test_telnet(mock_login):
    mock_login.return_value = (True, False)
    assert await scanner.test_telnet("host", 23, "user", "pass") is True


@pytest.mark.asyncio
@patch("edgewalker.modules.password_scan.scanner.SMBConnection")
async def test_test_smb(mock_smb):
    mock_smb.return_value.login.return_value = True
    assert await scanner.test_smb("host", 445, "user", "pass") is True

    mock_smb.return_value.login.side_effect = Exception("Fail")
    assert await scanner.test_smb("host", 445, "user", "wrong") is False


@pytest.mark.asyncio
async def test_telnet_scanner_attempt_login_success():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    # Mock _read_until patterns
    mock_reader.read.side_effect = [b"login: ", b"password: ", b"Welcome to the system\n$ "]

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is True
            assert kill is False


@pytest.mark.asyncio
async def test_telnet_scanner_attempt_login_fail():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader.read.side_effect = [b"login: ", b"password: ", b"Login incorrect\nlogin: "]

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is False


@pytest.mark.asyncio
async def test_smb_scanner_attempt_login():
    with patch("edgewalker.modules.password_scan.scanner.SMBConnection") as mock_smb:
        mock_smb.return_value.login.return_value = True
        s = scanner.SMBScanner("1.1.1.1", 445)
        res, kill = await s.attempt_login("user", "pass")
        assert res is True


@pytest.mark.asyncio
async def test_smb_scanner_attempt_login_error():
    s = scanner.SMBScanner("1.1.1.1", 445)
    with patch(
        "edgewalker.modules.password_scan.scanner.SMBConnection", side_effect=Exception("SMB error")
    ):
        res, kill = await s.attempt_login("u", "p")
        assert res is False


@pytest.mark.asyncio
async def test_ftp_scanner_attempt_login_error():
    s = scanner.FTPScanner("1.1.1.1", 21)
    with patch("asyncio.to_thread", side_effect=Exception("FTP error")):
        res, kill = await s.attempt_login("u", "p")
        assert res is False


def test_suppress_stderr():
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        with scanner.SuppressStderr():
            print("test", file=sys.stderr)
        assert sys.stderr.getvalue() == ""
    finally:
        sys.stderr = old_stderr


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_verbose():
    s = scanner.PasswordScanner(verbose=True)
    hosts = [{"ip": "1.1.1.1", "tcp_ports": [{"port": 22}]}]

    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        with patch("builtins.print"):
            with patch("edgewalker.utils.get_progress") as mock_get_progress:
                mock_progress = MagicMock()
                mock_get_progress.return_value.__enter__.return_value = mock_progress
                await s.scan_hosts(hosts)


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_verbose_multi():
    s = scanner.PasswordScanner(verbose=True)
    hosts = [
        {"ip": "1.1.1.1", "tcp_ports": [{"port": 22}]},
        {"ip": "1.1.1.2", "tcp_ports": [{"port": 22}]},
    ]
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        with patch("builtins.print"):
            await s.scan_hosts(hosts)


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_various_inputs():
    s = scanner.PasswordScanner()
    # Dict input
    hosts = [{"ip": "1.1.1.1", "tcp_ports": [{"port": 22}]}]
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts(hosts)

    # String input
    hosts = ["1.1.1.1"]
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts(hosts)


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_host_objects():
    # First Party
    from edgewalker.modules.port_scan.models import Host, TcpPort

    h = Host(ip="1.1.1.1", mac="00:11:22:33:44:55", tcp=[TcpPort(port=22, name="ssh")])
    s = scanner.PasswordScanner()
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts([h, h])  # Duplicate IP test
        assert s.scan_host.call_count == 1


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_dict_ports():
    s = scanner.PasswordScanner()
    hosts = [
        {
            "ip": "1.1.1.1",
            "mac": "00:11:22:33:44:55",
            "tcp": [{"port": 21}, {"port": 22}, {"port": 23}, {"port": 445}],
        }
    ]
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts(hosts)
        args, kwargs = s.scan_host.call_args
        assert args[1] == "00:11:22:33:44:55"
        assert set(args[2].keys()) == {"ftp", "ssh", "telnet", "smb"}


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_host_obj_ports():
    # First Party
    from edgewalker.modules.port_scan.models import Host, TcpPort

    h = Host(
        ip="1.1.1.1",
        mac="00:11:22:33:44:55",
        tcp=[
            TcpPort(port=21, name="ftp"),
            TcpPort(port=22, name="ssh"),
            TcpPort(port=23, name="telnet"),
            TcpPort(port=445, name="smb"),
        ],
    )
    s = scanner.PasswordScanner()
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts([h])
        args, kwargs = s.scan_host.call_args
        assert args[1] == "00:11:22:33:44:55"
        assert set(args[2].keys()) == {"ftp", "ssh", "telnet", "smb"}


@pytest.mark.asyncio
async def test_password_scanner_scan_host_progress():
    s = scanner.PasswordScanner()
    mock_progress = MagicMock()
    with patch(
        "edgewalker.modules.password_scan.scanner.SSHScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"ssh": 22}, progress=mock_progress)
        assert mock_progress.add_task.called


@pytest.mark.asyncio
async def test_password_scanner_scan_host_verbose():
    s = scanner.PasswordScanner(verbose=True)
    with patch(
        "edgewalker.modules.password_scan.scanner.SSHScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"ssh": 22})


@pytest.mark.asyncio
async def test_password_scanner_scan_interface():
    s = scanner.PasswordScanner()
    with patch.object(s, "scan_hosts", new_callable=AsyncMock) as mock_scan:
        await s.scan(hosts=[{"ip": "1.1.1.1"}])
        mock_scan.assert_called_once()

        await s.scan(hosts=None)
        mock_scan.assert_called_with([])


@pytest.mark.asyncio
async def test_password_scanner_scan_host_no_tasks():
    s = scanner.PasswordScanner()
    res = await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"unknown": 9999})
    assert res == []


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_no_work():
    s = scanner.PasswordScanner()
    res = await s.scan_hosts([])
    assert res.summary["total_hosts"] == 0


def test_load_credentials(tmp_path):
    creds_file = tmp_path / "creds.csv"
    creds_file.write_text("service,user,password\nssh,root,root\n")
    with patch("edgewalker.modules.password_scan.scanner.CREDS_CSV", creds_file):
        scanner._cred_cache = {}  # Reset cache
        res = scanner.load_credentials("ssh")
        assert len(res) == 1
        assert res[0] == ("root", "root")


def test_load_credentials_verbose():
    scanner._cred_cache = {"ssh": [("u", "p")]}
    scanner._printed_services = set()
    with patch("builtins.print") as mock_print:
        scanner.load_credentials("ssh")
        assert mock_print.called


def test_load_credentials_already_printed():
    scanner._cred_cache = {"ssh": [("u", "p")]}
    scanner._printed_services = {"ssh"}
    with patch("builtins.print") as mock_print:
        scanner.load_credentials("ssh")
        assert not mock_print.called


def test_load_credentials_not_found():
    scanner._cred_cache = {}
    with patch("edgewalker.modules.password_scan.scanner._load_csv", return_value={}):
        with patch("builtins.print") as mock_print:
            scanner.load_credentials("unknown")
            assert mock_print.called


def test_load_csv_no_file(tmp_path):
    with patch("edgewalker.modules.password_scan.scanner.CREDS_CSV", tmp_path / "nonexistent.csv"):
        assert scanner._load_csv() == {}


def test_load_csv_success(tmp_path):
    csv_file = tmp_path / "creds.csv"
    csv_file.write_text("service,user,password\nssh,root,root\nftp,admin,admin\n")
    with patch("edgewalker.modules.password_scan.scanner.CREDS_CSV", csv_file):
        res = scanner._load_csv()
        assert "ssh" in res
        assert "ftp" in res
        assert res["ssh"] == [("root", "root")]


@pytest.mark.asyncio
async def test_async_service_scanner_is_port_open():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "test"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return True, False

    s = TestScanner("1.1.1.1", 22)
    with patch("edgewalker.modules.password_scan.scanner.check_port_open", return_value=True):
        assert await s.is_port_open() is True


@pytest.mark.asyncio
async def test_async_service_scanner_port_closed():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "test"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return True, False

    s = TestScanner("1.1.1.1", 22)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=False):
        res = await s.scan()
        assert res.error == "port_closed"


@pytest.mark.asyncio
async def test_async_service_scanner_port_closed_rich_progress():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "test"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return True, False

    mock_progress = MagicMock()
    task_id = MagicMock()
    s = TestScanner("1.1.1.1", 22, rich_progress=(mock_progress, task_id))
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=False):
        await s.scan()
        mock_progress.update.assert_called_once_with(task_id, visible=False)


@pytest.mark.asyncio
async def test_async_service_scanner_scan_rich_progress():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return False, False

    mock_progress = MagicMock()
    task_id = MagicMock()
    s = TestScanner("1.1.1.1", 22, rich_progress=(mock_progress, task_id))
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            await s.scan()
            assert mock_progress.update.call_count >= 3  # start, advance, end


@pytest.mark.asyncio
async def test_async_service_scanner_scan_verbose_success():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return True, False

    s = TestScanner("1.1.1.1", 22, verbose=True)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            with patch("builtins.print") as mock_print:
                await s.scan()
                assert mock_print.called


@pytest.mark.asyncio
async def test_async_service_scanner_scan_callback():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return False, False

    cb = MagicMock()
    s = TestScanner("1.1.1.1", 22, progress_callback=cb)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            await s.scan()
            assert cb.called


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_callback_multi():
    cb = MagicMock()
    s = scanner.PasswordScanner(progress_callback=cb)
    hosts = [{"ip": "1.1.1.1", "tcp_ports": [{"port": 22}]}]
    with patch.object(s, "scan_host", new_callable=AsyncMock, return_value=[]):
        await s.scan_hosts(hosts)
        # scan_hosts doesn't call it directly but passes it to scan_host


@pytest.mark.asyncio
async def test_async_service_scanner_login_timeout():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            await asyncio.sleep(10)
            return True, False

    s = TestScanner("1.1.1.1", 22)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
                mock_settings.conn_timeout = 0.1
                res = await s.scan()
                assert res.login_attempt == scanner.StatusEnum.failed


@pytest.mark.asyncio
async def test_async_service_scanner_ratelimit():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return scanner.StatusEnum.ratelimit, False

    s = TestScanner("1.1.1.1", 22)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            res = await s.scan()
            assert res.login_attempt == scanner.StatusEnum.ratelimit


@pytest.mark.asyncio
async def test_async_service_scanner_kill_loop():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return False, True

    s = TestScanner("1.1.1.1", 22)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials",
            return_value=[("u1", "p1"), ("u2", "p2")],
        ):
            res = await s.scan()
            assert res.login_attempt == scanner.StatusEnum.failed


def test_scanner_metadata():
    for cls, name, enum in [
        (scanner.SSHScanner, "ssh", scanner.ServiceEnum.ssh),
        (scanner.FTPScanner, "ftp", scanner.ServiceEnum.ftp),
        (scanner.TelnetScanner, "telnet", scanner.ServiceEnum.telnet),
        (scanner.SMBScanner, "smb", scanner.ServiceEnum.smb),
    ]:
        s = cls("1.1.1.1", 0)
        assert s.service_name() == name
        assert s.service_enum() == enum


@pytest.mark.asyncio
async def test_telnet_scanner_read_until_timeout():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader.read.side_effect = asyncio.TimeoutError

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_no_login_prompt():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader.read.return_value = b"nothing"

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_read_until_empty():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader.read.return_value = b""

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_read_until_limit():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader.read.return_value = b"a" * 1024

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            res, kill = await s.attempt_login("user", "pass")
            assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_wait_closed_calls():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    # Fail at login prompt
    mock_reader.read.return_value = b"nothing"

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            await s.attempt_login("user", "pass")
            assert mock_writer.wait_closed.called


@pytest.mark.asyncio
async def test_telnet_scanner_read_until_timeout_inner():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)

            # Mock asyncio.wait_for to raise TimeoutError when called inside _read_until
            # The first call to wait_for is for open_connection (already mocked by patch)
            # The second call to wait_for is inside _read_until for reader.read
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                res, kill = await s.attempt_login("user", "pass")
                assert res is False
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)

            # Mock asyncio.wait_for to raise TimeoutError when called inside _read_until
            # The first call to wait_for is for open_connection (already mocked by patch)
            # The second call to wait_for is inside _read_until for reader.read
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                res, kill = await s.attempt_login("user", "pass")
                assert res is False
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)

            # Mock asyncio.wait_for to raise TimeoutError when called inside _read_until
            # The first call to wait_for is for open_connection (already mocked by patch)
            # The second call to wait_for is inside _read_until for reader.read
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                res, kill = await s.attempt_login("user", "pass")
                assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_read_until_limit_inner():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    # Mock reader.read to return 1024 bytes each time
    mock_reader.read.return_value = b"a" * 1024

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)

            res, kill = await s.attempt_login("user", "pass")
            assert res is False
            # It should have read 5 times to exceed 4096
            assert mock_reader.read.call_count >= 5


@pytest.mark.asyncio
async def test_telnet_scanner_attempt_login_timeout_real():
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_conn.side_effect = asyncio.TimeoutError
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)
            # We need to mock wait_for that wraps open_connection
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                res, kill = await s.attempt_login("user", "pass")
                assert res is False


@pytest.mark.asyncio
async def test_telnet_scanner_no_password_prompt_real():
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch(
        "asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)
    ):
        with patch("edgewalker.modules.password_scan.scanner.settings") as mock_settings:
            mock_settings.conn_timeout = 0.1
            mock_settings.cred_workers = 1
            s = scanner.TelnetScanner("1.1.1.1", 23)

            # First _read_until (login prompt) succeeds
            # Second _read_until (password prompt) fails
            with patch(
                "asyncio.wait_for", side_effect=[(mock_reader, mock_writer), b"login: ", b"nothing"]
            ):
                res, kill = await s.attempt_login("user", "pass")
                assert res is False


@pytest.mark.asyncio
async def test_async_service_scanner_scan_cred_found_callback():
    class TestScanner(scanner.AsyncServiceScanner):
        def service_name(self):
            return "ssh"

        def service_enum(self):
            return scanner.ServiceEnum.ssh

        async def attempt_login(self, u, p):
            return True, False

    cb = MagicMock()
    s = TestScanner("1.1.1.1", 22, progress_callback=cb)
    with patch.object(s, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            await s.scan()
            # Check if cred_found was called
            calls = [call[0][0] for call in cb.call_args_list]
            assert "cred_found" in calls


@pytest.mark.asyncio
async def test_scan_host_backward_compat():
    with patch(
        "edgewalker.modules.password_scan.scanner.PasswordScanner.scan_host", new_callable=AsyncMock
    ) as mock_scan:
        mock_scan.return_value = []
        res = await scanner.scan_host("1.1.1.1", {"ssh": 22})
        assert res["host"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_scan_host_backward_compat_vulnerable():
    with patch(
        "edgewalker.modules.password_scan.scanner.PasswordScanner.scan_host", new_callable=AsyncMock
    ) as mock_scan:
        # First Party
        from edgewalker.modules.password_scan.models import (
            CredentialsModel,
            PasswordScanResultModel,
        )

        mock_scan.return_value = [
            PasswordScanResultModel(
                ip="1.1.1.1",
                port=22,
                service=scanner.ServiceEnum.ssh,
                login_attempt=scanner.StatusEnum.successful,
                credentials=CredentialsModel(user="u", password="p"),
            )
        ]
        res = await scanner.scan_host("1.1.1.1", {"ssh": 22})
        assert res["services"]["ssh"]["status"] == "vulnerable"


@pytest.mark.asyncio
async def test_scan_backward_compat():
    with patch(
        "edgewalker.modules.password_scan.scanner.PasswordScanner.scan_hosts",
        new_callable=AsyncMock,
    ) as mock_scan:
        await scanner.scan(["1.1.1.1"])
        mock_scan.assert_called_once()


def test_init_cache_backward_compat():
    scanner.init_cache(None)  # Should do nothing


@pytest.mark.asyncio
async def test_test_service_unsupported():
    with pytest.raises(ValueError, match="Unsupported service"):
        await scanner._test_service("1.1.1.1", "unknown", 9999, None, 10, False)


@pytest.mark.asyncio
async def test_test_service_by_name():
    with patch(
        "edgewalker.modules.password_scan.scanner.SSHScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await scanner._test_service("1.1.1.1", "ssh", 2222, None, 10, False)
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_test_service_by_name_ftp():
    with patch(
        "edgewalker.modules.password_scan.scanner.FTPScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await scanner._test_service("1.1.1.1", "ftp", 2121, None, 10, False)
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_test_service_by_name_telnet():
    with patch(
        "edgewalker.modules.password_scan.scanner.TelnetScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await scanner._test_service("1.1.1.1", "telnet", 2323, None, 10, False)
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_test_service_by_name_smb():
    with patch(
        "edgewalker.modules.password_scan.scanner.SMBScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await scanner._test_service("1.1.1.1", "smb", 4455, None, 10, False)
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_scan_host_backward_compat_port_closed():
    with patch(
        "edgewalker.modules.password_scan.scanner.PasswordScanner.scan_host", new_callable=AsyncMock
    ) as mock_scan:
        # First Party
        from edgewalker.modules.password_scan.models import PasswordScanResultModel

        mock_scan.return_value = [
            PasswordScanResultModel(
                ip="1.1.1.1",
                port=22,
                service=scanner.ServiceEnum.ssh,
                login_attempt=scanner.StatusEnum.unknown,
                error="port_closed",
            )
        ]
        res = await scanner.scan_host("1.1.1.1", {"ssh": 22})
        assert res["services"]["ssh"]["status"] == "port_closed"


@pytest.mark.asyncio
async def test_telnet_scanner_exception():
    with patch("asyncio.open_connection", side_effect=Exception("Conn error")):
        s = scanner.TelnetScanner("1.1.1.1", 23)
        res, kill = await s.attempt_login("u", "p")
        assert res is False


@pytest.mark.asyncio
async def test_password_scanner_scan_host_by_name():
    s = scanner.PasswordScanner()
    with patch(
        "edgewalker.modules.password_scan.scanner.SSHScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"ssh": 2222})
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_password_scanner_scan_host_by_name_ftp():
    s = scanner.PasswordScanner()
    with patch(
        "edgewalker.modules.password_scan.scanner.FTPScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"ftp": 2121})
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_password_scanner_scan_host_by_name_telnet():
    s = scanner.PasswordScanner()
    with patch(
        "edgewalker.modules.password_scan.scanner.TelnetScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"telnet": 2323})
        mock_scan.assert_called_once()


@pytest.mark.asyncio
async def test_password_scanner_scan_host_by_name_smb():
    s = scanner.PasswordScanner()
    with patch(
        "edgewalker.modules.password_scan.scanner.SMBScanner.scan", new_callable=AsyncMock
    ) as mock_scan:
        await s.scan_host("1.1.1.1", "00:11:22:33:44:55", {"smb": 4455})
        mock_scan.assert_called_once()
