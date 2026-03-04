# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.password_scan.scanner import (
    FTPScanner,
    PasswordScanner,
    SMBScanner,
    SSHScanner,
    check_port_open,
    load_credentials,
)


def test_check_port_open():
    with patch("socket.socket") as mock_sock:
        mock_sock.return_value.__enter__.return_value.connect_ex.return_value = 0
        assert check_port_open("127.0.0.1", 80) is True


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


def test_load_credentials():
    with patch("edgewalker.modules.password_scan.scanner._cred_cache", {"ssh": [("u", "p")]}):
        creds = load_credentials("ssh", top_n=1)
        assert creds == [("u", "p")]
