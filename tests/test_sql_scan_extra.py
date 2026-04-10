# Standard Library
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.sql_scan.models import SqlStatusEnum
from edgewalker.modules.sql_scan.scanner import (
    MongoDbScanner,
    MySqlScanner,
    PostgreSqlScanner,
    RedisScanner,
    SqlScanner,
)


@pytest.mark.asyncio
async def test_mysql_scanner_success():
    with patch("edgewalker.modules.sql_scan.scanner.aiomysql") as mock_mysql:
        mock_conn = AsyncMock()
        mock_mysql.connect = AsyncMock(return_value=mock_conn)
        mock_cur = AsyncMock()
        # aiomysql cursor() returns an async context manager, it's not a coroutine
        mock_conn.cursor = MagicMock(return_value=mock_cur)
        # The cursor itself is used as an async context manager
        mock_cur.__aenter__ = AsyncMock(return_value=mock_cur)
        mock_cur.__aexit__ = AsyncMock(return_value=None)
        mock_cur.fetchone = AsyncMock(return_value=["8.0.23"])
        mock_cur.fetchall = AsyncMock(return_value=[["db1"], ["db2"]])

        scanner = MySqlScanner("1.1.1.1", 3306)
        status, info = await scanner.attempt_login("user", "pass")

        assert status == SqlStatusEnum.successful
        assert info["version"] == "8.0.23"
        assert info["databases"] == ["db1", "db2"]


@pytest.mark.asyncio
async def test_postgresql_scanner_success():
    with patch("edgewalker.modules.sql_scan.scanner.asyncpg") as mock_pg:
        mock_conn = AsyncMock()
        mock_pg.connect = AsyncMock(return_value=mock_conn)
        mock_conn.fetchval.return_value = "13.2"
        mock_conn.fetch.return_value = [{"datname": "db1"}, {"datname": "db2"}]

        scanner = PostgreSqlScanner("1.1.1.1", 5432)
        status, info = await scanner.attempt_login("user", "pass")

        assert status == SqlStatusEnum.successful
        assert info["version"] == "13.2"
        assert info["databases"] == ["db1", "db2"]


@pytest.mark.asyncio
async def test_redis_scanner_success():
    with patch("edgewalker.modules.sql_scan.scanner.redis") as mock_redis:
        mock_r = AsyncMock()
        mock_redis.Redis.return_value = mock_r
        mock_r.info.return_value = {"redis_version": "6.2.1"}

        scanner = RedisScanner("1.1.1.1", 6379)
        status, info = await scanner.attempt_login("", "pass")

        assert status == SqlStatusEnum.successful
        assert info["version"] == "6.2.1"


@pytest.mark.asyncio
async def test_mongodb_scanner_success():
    with patch("edgewalker.modules.sql_scan.scanner.AsyncIOMotorClient") as mock_motor:
        mock_client = MagicMock()
        mock_motor.return_value = mock_client
        mock_client.server_info = AsyncMock(return_value={"version": "4.4.4"})
        mock_client.list_database_names = AsyncMock(return_value=["db1", "db2"])

        scanner = MongoDbScanner("1.1.1.1", 27017)
        status, info = await scanner.attempt_login("user", "pass")

        assert status == SqlStatusEnum.successful
        assert info["version"] == "4.4.4"
        assert info["databases"] == ["db1", "db2"]


@pytest.mark.asyncio
async def test_sql_scanner_no_hosts():
    scanner = SqlScanner()
    result = await scanner.scan(hosts=[])
    assert result.summary["total_services"] == 0


@pytest.mark.asyncio
async def test_sql_scanner_timeout():
    with patch(
        "edgewalker.modules.sql_scan.scanner.MySqlScanner.attempt_login", new_callable=AsyncMock
    ) as mock_login:
        mock_login.side_effect = asyncio.TimeoutError()
        scanner = MySqlScanner("1.1.1.1", 3306)
        # We need to test the scan() method which handles the timeout
        with patch(
            "edgewalker.modules.sql_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            res = await scanner.scan()
            assert res.status == SqlStatusEnum.failed


@pytest.mark.asyncio
async def test_sql_scanner_exception():
    with patch(
        "edgewalker.modules.sql_scan.scanner.MySqlScanner.attempt_login", new_callable=AsyncMock
    ) as mock_login:
        mock_login.side_effect = Exception("error")
        scanner = MySqlScanner("1.1.1.1", 3306)
        with patch(
            "edgewalker.modules.sql_scan.scanner.load_credentials", return_value=[("u", "p")]
        ):
            res = await scanner.scan()
            assert res.status == SqlStatusEnum.failed


@pytest.mark.asyncio
async def test_mysql_scanner_no_aiomysql():
    with patch("edgewalker.modules.sql_scan.scanner.aiomysql", None):
        scanner = MySqlScanner("1.1.1.1", 3306)
        status, info = await scanner.attempt_login("u", "p")
        assert status == SqlStatusEnum.unknown
        assert "not installed" in info["error"]


@pytest.mark.asyncio
async def test_postgresql_scanner_no_asyncpg():
    with patch("edgewalker.modules.sql_scan.scanner.asyncpg", None):
        scanner = PostgreSqlScanner("1.1.1.1", 5432)
        status, info = await scanner.attempt_login("u", "p")
        assert status == SqlStatusEnum.unknown
        assert "not installed" in info["error"]


@pytest.mark.asyncio
async def test_redis_scanner_no_redis():
    with patch("edgewalker.modules.sql_scan.scanner.redis", None):
        scanner = RedisScanner("1.1.1.1", 6379)
        status, info = await scanner.attempt_login("u", "p")
        assert status == SqlStatusEnum.unknown
        assert "not installed" in info["error"]


@pytest.mark.asyncio
async def test_mongodb_scanner_no_motor():
    with patch("edgewalker.modules.sql_scan.scanner.AsyncIOMotorClient", None):
        scanner = MongoDbScanner("1.1.1.1", 27017)
        status, info = await scanner.attempt_login("u", "p")
        assert status == SqlStatusEnum.unknown
        assert "not installed" in info["error"]
