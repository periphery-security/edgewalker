# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.password_scan.models import StatusEnum
from edgewalker.modules.password_scan.scanner import (
    FTPScanner,
    PasswordScanner,
    SMBScanner,
    SSHScanner,
    TelnetScanner,
    check_port_open,
)


def test_check_port_open():
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.return_value.connect_ex.return_value = 0
        assert check_port_open("127.0.0.1", 80) is True


@pytest.mark.asyncio
async def test_password_scanner_scan_port_closed():
    scanner = SSHScanner("1.1.1.1", 22)
    with patch.object(scanner, "is_port_open", new_callable=AsyncMock, return_value=False):
        result = await scanner.scan()
        assert result.login_attempt == StatusEnum.unknown
        assert result.error == "port_closed"


@pytest.mark.asyncio
async def test_password_scanner_scan_ratelimit():
    scanner = SSHScanner("1.1.1.1", 22)
    with patch.object(scanner, "is_port_open", new_callable=AsyncMock, return_value=True):
        with patch(
            "edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            with patch.object(
                scanner,
                "attempt_login",
                new_callable=AsyncMock,
                return_value=(StatusEnum.ratelimit, False),
            ):
                result = await scanner.scan()
                assert result.login_attempt == StatusEnum.ratelimit


@pytest.mark.asyncio
async def test_telnet_scanner_success():
    scanner = TelnetScanner("1.1.1.1", 23)
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
        mock_open.return_value = (mock_reader, mock_writer)

        # Mock responses for _read_until
        # 1. login prompt, 2. password prompt, 3. success
        mock_reader.read.side_effect = [b"login:", b"Password:", b"Welcome"]

        status, kill = await scanner.attempt_login("user", "pass")
        assert status is True
        assert kill is False


@pytest.mark.asyncio
async def test_ftp_scanner():
    scanner = FTPScanner("127.0.0.1", 21)
    with patch("ftplib.FTP") as mock_ftp:
        mock_ftp.return_value.__enter__.return_value.connect = MagicMock()
        mock_ftp.return_value.__enter__.return_value.login = MagicMock()
        res, kill = await scanner.attempt_login("user", "pass")
        assert res is True


@pytest.mark.asyncio
async def test_smb_scanner():
    scanner = SMBScanner("127.0.0.1", 445)
    with patch("edgewalker.modules.password_scan.scanner.SMBConnection") as mock_smb:
        mock_smb.return_value.login = MagicMock()
        res, kill = await scanner.attempt_login("user", "pass")
        assert res is True


@pytest.mark.asyncio
async def test_password_scanner_hosts():
    scanner = PasswordScanner()
    hosts = [{"ip": "127.0.0.1", "tcp": [{"port": 22}]}]

    with patch.object(SSHScanner, "is_port_open", return_value=True):
        with patch.object(SSHScanner, "attempt_login", return_value=(True, False)):
            with patch(
                "edgewalker.modules.password_scan.scanner.load_credentials",
                return_value=[("admin", "admin")],
            ):
                results = await scanner.scan_hosts(hosts)
                assert results.summary["vulnerable_hosts"] == 1


@pytest.mark.asyncio
async def test_password_scanner_scan_hosts_various_inputs():
    # First Party
    from edgewalker.modules.password_scan.models import PasswordScanResultModel, ServiceEnum

    scanner = PasswordScanner()
    # Mix of dicts and objects

    class MockHost:
        def __init__(self, ip, mac):
            self.ip = ip
            self.mac = mac
            self.tcp = [MagicMock(port=22)]

    hosts = [
        {"ip": "1.1.1.1", "mac": "AA:BB", "tcp": [{"port": 22}]},
        MockHost("2.2.2.2", "CC:DD"),
        "3.3.3.3",  # Simple string
    ]

    with patch.object(SSHScanner, "scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = PasswordScanResultModel(
            ip="1.1.1.1", port=22, service=ServiceEnum.ssh, login_attempt=StatusEnum.failed
        )
        results = await scanner.scan_hosts(hosts)
        assert results.summary["total_hosts"] == 3


@pytest.mark.asyncio
async def test_password_scan_wrappers():
    # First Party
    from edgewalker.modules.password_scan.scanner import (
        _test_service,
        test_ftp,
        test_smb,
        test_ssh,
        test_telnet,
    )

    with patch.object(
        SSHScanner, "attempt_login", new_callable=AsyncMock, return_value=(True, False)
    ):
        assert await test_ssh("1.1.1.1", 22, "u", "p") is True

    with patch.object(
        FTPScanner, "attempt_login", new_callable=AsyncMock, return_value=(True, False)
    ):
        assert await test_ftp("1.1.1.1", 21, "u", "p") is True

    with patch.object(
        SMBScanner, "attempt_login", new_callable=AsyncMock, return_value=(True, False)
    ):
        assert await test_smb("1.1.1.1", 445, "u", "p") is True

    with patch.object(
        TelnetScanner, "attempt_login", new_callable=AsyncMock, return_value=(True, False)
    ):
        assert await test_telnet("1.1.1.1", 23, "u", "p") is True

    with patch.object(SSHScanner, "scan", new_callable=AsyncMock) as mock_scan:
        await _test_service("1.1.1.1", "ssh", 22, MagicMock(), 10, False)
        assert mock_scan.called
