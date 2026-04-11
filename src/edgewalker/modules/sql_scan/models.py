"""SQL Scan Models."""

from __future__ import annotations

# Standard Library
from enum import Enum
from typing import Any, Optional

# Third Party
from pydantic import BaseModel, Field


class SqlServiceEnum(str, Enum):
    """Supported SQL services."""

    mysql = "mysql"
    postgresql = "postgresql"
    mssql = "mssql"
    redis = "redis"
    mongodb = "mongodb"


class SqlStatusEnum(str, Enum):
    """Status of SQL scan."""

    successful = "successful"
    failed = "failed"
    ratelimit = "ratelimit"
    unknown = "unknown"
    anonymous = "anonymous"


class SqlCredentialsModel(BaseModel):
    """Credentials found for a SQL service."""

    user: str
    password: str


class SqlScanResultModel(BaseModel):
    """Result of a single SQL service scan."""

    ip: str
    port: int
    service: SqlServiceEnum
    status: SqlStatusEnum
    credentials: Optional[SqlCredentialsModel] = None
    version: Optional[str] = None
    databases: list[str] = Field(default_factory=list)
    privileges: Optional[str] = None
    error: Optional[str] = None
    tested_count: int = 0
    device_correlation_id: Optional[str] = None


class SqlScanModel(BaseModel):
    """Complete SQL scan results."""

    id: str
    device_id: str
    version: str
    module: str = "sql_scan"
    module_version: str = "0.1.0"
    results: list[SqlScanResultModel]
    summary: dict[str, Any]
