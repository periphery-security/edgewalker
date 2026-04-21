# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.sql_scan.models import SqlServiceEnum, SqlStatusEnum
from edgewalker.modules.sql_scan.scanner import (
    MongoDbScanner,
    MySqlScanner,
    PostgreSqlScanner,
    RedisScanner,
    SqlScanner,
)


@pytest.mark.asyncio
async def test_mysql_scanner_exception_in_attempt_login():
    """Test MySqlScanner.attempt_login exception handling."""
    with patch("edgewalker.modules.sql_scan.scanner.aiomysql") as mock_mysql:
        mock_mysql.connect.side_effect = Exception("Connection failed")
        scanner = MySqlScanner("1.1.1.1", 3306)
        status, info = await scanner.attempt_login("user", "pass")
        assert status == SqlStatusEnum.failed
        assert info is None


@pytest.mark.asyncio
async def test_postgresql_scanner_exception_in_attempt_login():
    """Test PostgreSqlScanner.attempt_login exception handling."""
    with patch("edgewalker.modules.sql_scan.scanner.asyncpg") as mock_pg:
        mock_pg.connect.side_effect = Exception("Connection failed")
        scanner = PostgreSqlScanner("1.1.1.1", 5432)
        status, info = await scanner.attempt_login("user", "pass")
        assert status == SqlStatusEnum.failed
        assert info is None


@pytest.mark.asyncio
async def test_redis_scanner_exception_in_attempt_login():
    """Test RedisScanner.attempt_login exception handling."""
    with patch("edgewalker.modules.sql_scan.scanner.redis") as mock_redis:
        mock_redis.Redis.side_effect = Exception("Connection failed")
        scanner = RedisScanner("1.1.1.1", 6379)
        status, info = await scanner.attempt_login("user", "pass")
        assert status == SqlStatusEnum.failed
        assert info is None


@pytest.mark.asyncio
async def test_mongodb_scanner_exception_in_attempt_login():
    """Test MongoDbScanner.attempt_login exception handling."""
    with patch("edgewalker.modules.sql_scan.scanner.AsyncIOMotorClient") as mock_motor:
        mock_motor.side_effect = Exception("Connection failed")
        scanner = MongoDbScanner("1.1.1.1", 27017)
        status, info = await scanner.attempt_login("user", "pass")
        assert status == SqlStatusEnum.failed
        assert info is None


@pytest.mark.asyncio
async def test_sql_scanner_invalid_hosts_type():
    """Test SqlScanner.scan with invalid hosts type."""
    scanner = SqlScanner()
    # Passing something that is not a list
    result = await scanner.scan(hosts="not a list")
    assert result.results == []
    assert result.summary["total_services"] == 0


@pytest.mark.asyncio
async def test_sql_scanner_no_credentials_warning():
    """Test SqlScanner.scan when no credentials are found (covers line 97)."""
    scanner = MySqlScanner("1.1.1.1", 3306)

    with patch("edgewalker.modules.sql_scan.scanner.load_credentials") as mock_load:
        mock_creds = MagicMock(spec=list)
        mock_creds.__contains__.return_value = True  # Pretend ("", "") is already there
        mock_creds.__len__.return_value = 0  # Pretend it's empty
        mock_load.return_value = mock_creds

        # This should trigger "if not creds:"
        await scanner.scan()


@pytest.mark.asyncio
async def test_sql_scanner_with_credentials_info():
    """Test SqlScanner.scan with credentials to trigger info log (covers line 99)."""
    scanner = MySqlScanner("1.1.1.1", 3306)
    with patch(
        "edgewalker.modules.sql_scan.scanner.load_credentials", return_value=[("user", "pass")]
    ):
        with patch.object(
            scanner, "attempt_login", AsyncMock(return_value=(SqlStatusEnum.failed, None))
        ):
            await scanner.scan()


@pytest.mark.asyncio
async def test_service_enums():
    """Test service_enum methods for coverage."""
    assert MySqlScanner("1.1.1.1", 3306).service_enum() == SqlServiceEnum.mysql
    assert PostgreSqlScanner("1.1.1.1", 5432).service_enum() == SqlServiceEnum.postgresql
    assert RedisScanner("1.1.1.1", 6379).service_enum() == SqlServiceEnum.redis
    assert MongoDbScanner("1.1.1.1", 27017).service_enum() == SqlServiceEnum.mongodb


@pytest.mark.asyncio
async def test_mongodb_scanner_anonymous_uri():
    """Test MongoDbScanner.attempt_login with anonymous login (covers line 301)."""
    with patch("edgewalker.modules.sql_scan.scanner.AsyncIOMotorClient") as mock_motor:
        mock_client = MagicMock()
        mock_motor.return_value = mock_client
        mock_client.server_info = AsyncMock(return_value={"version": "4.4.4"})
        mock_client.list_database_names = AsyncMock(return_value=["db1"])

        scanner = MongoDbScanner("1.1.1.1", 27017)
        status, info = await scanner.attempt_login("", "")  # Anonymous
        assert status == SqlStatusEnum.anonymous
        assert mock_motor.call_args[0][0] == "mongodb://1.1.1.1:27017/"
