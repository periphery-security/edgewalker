"""Web Scan Models."""

from __future__ import annotations

# Standard Library
from typing import Any, Optional

# Third Party
from pydantic import BaseModel, Field


class SecurityHeadersModel(BaseModel):
    """Security headers found on a web service."""

    csp: bool = False
    hsts: bool = False
    x_frame_options: bool = False
    x_content_type_options: bool = False
    referrer_policy: bool = False
    permissions_policy: bool = False


class TlsInfoModel(BaseModel):
    """TLS/SSL information for a web service."""

    protocol: Optional[str] = None
    cipher: Optional[str] = None
    issuer: Optional[str] = None
    expires: Optional[str] = None
    expired: bool = False


class WebScanResultModel(BaseModel):
    """Result of a single web service scan."""

    ip: str
    port: int
    protocol: str  # http or https
    status_code: Optional[int] = None
    server: Optional[str] = None
    title: Optional[str] = None
    headers: SecurityHeadersModel = Field(default_factory=SecurityHeadersModel)
    tls: Optional[TlsInfoModel] = None
    sensitive_files: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class WebScanModel(BaseModel):
    """Complete web scan results."""

    id: str
    device_id: str
    version: str
    module: str = "web_scan"
    module_version: str = "0.1.0"
    results: list[WebScanResultModel]
    summary: dict[str, Any]
