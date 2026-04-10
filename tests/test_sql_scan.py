# Standard Library
from unittest.mock import AsyncMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.sql_scan.models import SqlStatusEnum
from edgewalker.modules.sql_scan.scanner import SqlScanner


@pytest.mark.asyncio
async def test_sql_scan_anonymous_check():
    """Test that anonymous check is performed even if no credentials are found."""
    scanner = SqlScanner()

    # Mock load_credentials to return empty list
    with patch("edgewalker.modules.sql_scan.scanner.load_credentials") as mock_load:
        mock_load.return_value = []

        # Mock attempt_login to succeed for anonymous
        with patch(
            "edgewalker.modules.sql_scan.scanner.MySqlScanner.attempt_login", new_callable=AsyncMock
        ) as mock_attempt:
            mock_attempt.return_value = (SqlStatusEnum.anonymous, {"version": "8.0.0"})

            hosts = [{"ip": "127.0.0.1", "tcp_ports": [{"port": 3306}]}]

            result = await scanner.scan(hosts=hosts)

            assert len(result.results) == 1
            scan_result = result.results[0]

            assert scan_result.status == SqlStatusEnum.anonymous
            assert scan_result.version == "8.0.0"
            assert scan_result.tested_count == 1  # Only anonymous check


@pytest.mark.asyncio
async def test_sql_scan_with_credentials():
    """Test that credentials from load_credentials are used."""
    scanner = SqlScanner()

    with patch("edgewalker.modules.sql_scan.scanner.load_credentials") as mock_load:
        mock_load.return_value = [("root", "password")]

        with patch(
            "edgewalker.modules.sql_scan.scanner.MySqlScanner.attempt_login", new_callable=AsyncMock
        ) as mock_attempt:
            # First attempt (anonymous) fails, second (root:password) succeeds
            mock_attempt.side_effect = [
                (SqlStatusEnum.failed, None),
                (SqlStatusEnum.successful, {"version": "8.0.0", "databases": ["test"]}),
            ]

            hosts = [{"ip": "127.0.0.1", "tcp_ports": [{"port": 3306}]}]

            result = await scanner.scan(hosts=hosts)

            assert len(result.results) == 1
            scan_result = result.results[0]

            assert scan_result.status == SqlStatusEnum.successful
            assert scan_result.credentials.user == "root"
            assert scan_result.credentials.password == "password"
            assert scan_result.tested_count == 2


@pytest.mark.asyncio
async def test_sql_scan_missing_dependency():
    """Test that missing dependencies result in unknown status and error message."""
    scanner = SqlScanner()

    with patch("edgewalker.modules.sql_scan.scanner.load_credentials") as mock_load:
        mock_load.return_value = [("admin", "admin")]

        # Mock the attempt_login method of MySqlScanner to simulate missing aiomysql
        with patch(
            "edgewalker.modules.sql_scan.scanner.MySqlScanner.attempt_login", new_callable=AsyncMock
        ) as mock_attempt:
            mock_attempt.return_value = (SqlStatusEnum.unknown, {"error": "aiomysql not installed"})

            hosts = [{"ip": "127.0.0.1", "tcp_ports": [{"port": 3306}]}]

            result = await scanner.scan(hosts=hosts)

            assert len(result.results) == 1
            scan_result = result.results[0]

            assert scan_result.status == SqlStatusEnum.unknown
            assert scan_result.error == "aiomysql not installed"
            assert scan_result.tested_count == 1  # Breaks after first attempt (anonymous)
