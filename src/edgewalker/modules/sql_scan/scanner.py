"""SQL Scan Module.

Tests default/weak credentials and misconfigurations against SQL services.
"""

from __future__ import annotations

# Standard Library
import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

# Third Party
from loguru import logger

# First Party
from edgewalker import __version__
from edgewalker.core.config import settings
from edgewalker.modules import ScanModule
from edgewalker.modules.password_scan.scanner import load_credentials
from edgewalker.modules.sql_scan.models import (
    SqlCredentialsModel,
    SqlScanModel,
    SqlScanResultModel,
    SqlServiceEnum,
    SqlStatusEnum,
)
from edgewalker.utils import get_device_id

# Optional dependencies
try:
    # Third Party
    import aiomysql
except ImportError:
    aiomysql = None

try:
    # Third Party
    import asyncpg
except ImportError:
    asyncpg = None

try:
    # Third Party
    import redis.asyncio as redis
except ImportError:
    redis = None

try:
    # Third Party
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError:
    AsyncIOMotorClient = None


class BaseSqlScanner(ABC):
    """Abstract base class for SQL service scanners."""

    def __init__(
        self,
        ip: str,
        port: int,
        top_n: Optional[int] = None,
        semaphore: Optional[asyncio.Semaphore] = None,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the BaseSqlScanner."""
        self.ip = ip
        self.port = port
        self.top_n = top_n
        self.semaphore = semaphore or asyncio.Semaphore(settings.cred_workers)
        self.progress_callback = progress_callback

    @abstractmethod
    def service_enum(self) -> SqlServiceEnum:
        """Return the service enum."""
        ...

    @abstractmethod
    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[SqlStatusEnum, Optional[dict[str, Any]]]:
        """Attempt login and return status and optional info."""
        ...

    async def scan(self) -> SqlScanResultModel:
        """Perform the scan."""
        creds = load_credentials(self.service_enum().value, self.top_n)

        # Add anonymous check for all services to be thorough
        # (Some services like Redis/MongoDB are often open without any user/pass)
        if ("", "") not in creds:
            creds.insert(0, ("", ""))

        if not creds:
            logger.warning(f"No credentials found for {self.service_enum().value.upper()} audit")
        else:
            logger.info(
                f"Auditing {self.service_enum().value.upper()} on {self.ip}:{self.port} "
                f"-- testing {len(creds)} credentials"
            )

        status = SqlStatusEnum.failed
        found_info = None
        found_cred = None
        tested_count = 0

        for user, pw in creds:
            tested_count += 1
            logger.debug(
                f"SQL: Attempting {self.service_enum().value} login on {self.ip}:{self.port} "
                f"with user='{user}' password='{pw}'"
            )
            async with self.semaphore:
                try:
                    res_status, info = await asyncio.wait_for(
                        self.attempt_login(user, pw), timeout=settings.conn_timeout + 2
                    )
                    if res_status in [SqlStatusEnum.successful, SqlStatusEnum.anonymous]:
                        logger.success(
                            f"SQL VULNERABILITY FOUND: {self.service_enum().value.upper()} "
                            f"on {self.ip}:{self.port} with {user or 'anonymous'}:{pw} "
                            f"({res_status.value})"
                        )
                        status = res_status
                        found_info = info
                        if user or pw:
                            found_cred = SqlCredentialsModel(user=user, password=pw)
                        break
                    elif res_status == SqlStatusEnum.unknown:
                        error_msg = info.get("error", "Unknown error") if info else "Unknown error"
                        logger.warning(f"SQL: {self.service_enum().value} scan error: {error_msg}")
                        status = res_status
                        found_info = info
                        # Don't break on unknown, try other creds if it was just a connection issue
                        # but if it's a missing dependency, we should break.
                        if "not installed" in error_msg:
                            break
                    else:
                        logger.debug(
                            f"SQL: {self.service_enum().value} login failed for {user}:{pw}"
                        )
                except asyncio.TimeoutError:
                    logger.debug(
                        f"SQL: {self.service_enum().value} timeout for {user}:{pw} "
                        f"on {self.ip}:{self.port}"
                    )
                except Exception as e:
                    logger.debug(
                        f"SQL: {self.service_enum().value} error for {user}:{pw} "
                        f"on {self.ip}:{self.port}: {e}"
                    )

        result = SqlScanResultModel(
            ip=self.ip,
            port=self.port,
            service=self.service_enum(),
            status=status,
            credentials=found_cred,
            tested_count=tested_count,
            error=found_info.get("error") if found_info else None,
        )

        if found_info:
            result.version = found_info.get("version")
            result.databases = found_info.get("databases", [])
            result.privileges = found_info.get("privileges")

        return result


class MySqlScanner(BaseSqlScanner):
    """MySQL scanner."""

    def service_enum(self) -> SqlServiceEnum:
        """Return the MySQL service enum."""
        return SqlServiceEnum.mysql

    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[SqlStatusEnum, Optional[dict[str, Any]]]:
        """Attempt MySQL login."""
        if not aiomysql:
            return SqlStatusEnum.unknown, {"error": "aiomysql not installed"}

        try:
            logger.debug(f"MySQL: Connecting to {self.ip}:{self.port} as {username}...")
            conn = await aiomysql.connect(
                host=self.ip,
                port=self.port,
                user=username,
                password=password,
                connect_timeout=settings.conn_timeout,
            )
            logger.debug(f"MySQL: Connection successful for {username}")
            async with conn.cursor() as cur:
                await cur.execute("SELECT VERSION()")
                version = await cur.fetchone()

                await cur.execute("SHOW DATABASES")
                dbs = await cur.fetchall()
                db_list = [d[0] for d in dbs]

            conn.close()
            return SqlStatusEnum.successful, {
                "version": version[0] if version else None,
                "databases": db_list,
            }
        except Exception as e:
            logger.debug(f"MySQL: Login failed for {username}: {e}")
            return SqlStatusEnum.failed, None


class PostgreSqlScanner(BaseSqlScanner):
    """PostgreSQL scanner."""

    def service_enum(self) -> SqlServiceEnum:
        """Return the PostgreSQL service enum."""
        return SqlServiceEnum.postgresql

    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[SqlStatusEnum, Optional[dict[str, Any]]]:
        """Attempt PostgreSQL login."""
        if not asyncpg:
            return SqlStatusEnum.unknown, {"error": "asyncpg not installed"}

        try:
            logger.debug(f"PostgreSQL: Connecting to {self.ip}:{self.port} as {username}...")
            conn = await asyncpg.connect(
                user=username,
                password=password,
                host=self.ip,
                port=self.port,
                database="postgres",  # Explicitly target postgres DB
                ssl="disable",  # Disable SSL for initial probe
                timeout=settings.conn_timeout,
            )
            logger.debug(f"PostgreSQL: Connection successful for {username}")
            version = await conn.fetchval("SELECT version()")
            dbs = await conn.fetch("SELECT datname FROM pg_database WHERE datistemplate = false")
            db_list = [d["datname"] for d in dbs]

            await conn.close()
            return SqlStatusEnum.successful, {"version": version, "databases": db_list}
        except Exception as e:
            logger.debug(f"PostgreSQL: Login failed for {username}: {e}")
            return SqlStatusEnum.failed, None


class RedisScanner(BaseSqlScanner):
    """Redis scanner."""

    def service_enum(self) -> SqlServiceEnum:
        """Return the Redis service enum."""
        return SqlServiceEnum.redis

    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[SqlStatusEnum, Optional[dict[str, Any]]]:
        """Attempt Redis login."""
        if not redis:
            return SqlStatusEnum.unknown, {"error": "redis not installed"}

        try:
            r = redis.Redis(
                host=self.ip,
                port=self.port,
                password=password if password else None,
                socket_timeout=settings.conn_timeout,
            )
            info = await r.info()
            version = info.get("redis_version")

            status = SqlStatusEnum.successful if password else SqlStatusEnum.anonymous
            await r.aclose()
            return status, {"version": version}
        except Exception:
            return SqlStatusEnum.failed, None


class MongoDbScanner(BaseSqlScanner):
    """MongoDB scanner."""

    def service_enum(self) -> SqlServiceEnum:
        """Return the MongoDB service enum."""
        return SqlServiceEnum.mongodb

    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[SqlStatusEnum, Optional[dict[str, Any]]]:
        """Attempt MongoDB login."""
        if not AsyncIOMotorClient:
            return SqlStatusEnum.unknown, {"error": "motor not installed"}

        try:
            if username:
                uri = f"mongodb://{username}:{password}@{self.ip}:{self.port}/"
            else:
                uri = f"mongodb://{self.ip}:{self.port}/"

            client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=settings.conn_timeout * 1000)
            info = await client.server_info()
            version = info.get("version")

            dbs = await client.list_database_names()

            status = SqlStatusEnum.successful if username else SqlStatusEnum.anonymous
            client.close()
            return status, {"version": version, "databases": dbs}
        except Exception:
            return SqlStatusEnum.failed, None


class SqlScanner(ScanModule):
    """Coordinator for SQL scanning."""

    name = "SQL Scan"
    slug = "sql_scan"
    description = "Audit SQL services for default credentials and misconfigurations"

    def __init__(
        self,
        target: str | None = None,
        top_n: Optional[int] = 10,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the SqlScanner."""
        self.target = target
        self.top_n = top_n
        self.verbose = verbose
        self.progress_callback = progress_callback
        self.port_map = {
            3306: MySqlScanner,
            5432: PostgreSqlScanner,
            6379: RedisScanner,
            27017: MongoDbScanner,
        }
        self.semaphore = asyncio.Semaphore(settings.cred_workers)

    async def scan(self, **kwargs: object) -> SqlScanModel:
        """Execute the scan asynchronously."""
        hosts = kwargs.get("hosts", [])
        if not isinstance(hosts, list):
            hosts = []

        logger.debug(f"SQL scan checking {len(hosts)} hosts")
        all_results = []
        tasks = []

        for h in hosts:
            ip = h.get("ip", "")
            ports = h.get("tcp_ports") or h.get("tcp", [])
            logger.debug(f"Checking host {ip} with {len(ports)} ports")
            for p in ports:
                port_num = p.get("port")
                scanner_cls = self.port_map.get(port_num)
                if scanner_cls:
                    logger.info(f"Found SQL service on {ip}:{port_num}")
                    scanner = scanner_cls(
                        ip, port_num, self.top_n, self.semaphore, self.progress_callback
                    )
                    tasks.append(scanner.scan())

        if tasks:
            all_results = await asyncio.gather(*tasks)
        else:
            logger.debug("No SQL services found to audit")

        summary = {
            "total_services": len(all_results),
            "vulnerable_services": len([
                r
                for r in all_results
                if r.status in [SqlStatusEnum.successful, SqlStatusEnum.anonymous]
            ]),
            "credentials_found": len([r for r in all_results if r.credentials]),
            "anonymous_access": len([
                r for r in all_results if r.status == SqlStatusEnum.anonymous
            ]),
        }

        return SqlScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
            version=__version__,
            results=all_results,
            summary=summary,
        )
