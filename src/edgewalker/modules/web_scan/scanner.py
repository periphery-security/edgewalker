"""Web Scan Module.

Performs non-intrusive security audits on discovered web services.
"""

from __future__ import annotations

# Standard Library
import asyncio
import ssl
import uuid
from datetime import datetime
from typing import Any, Callable, Optional

# Third Party
import httpx
from bs4 import BeautifulSoup
from loguru import logger

# First Party
from edgewalker import __version__
from edgewalker.core.config import settings
from edgewalker.modules import ScanModule
from edgewalker.modules.web_scan.models import (
    SecurityHeadersModel,
    TlsInfoModel,
    WebScanModel,
    WebScanResultModel,
)
from edgewalker.utils import get_device_id

SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    "phpinfo.php",
    "backup.sql",
    "config.php.bak",
    "wp-config.php",
    ".htaccess",
    "server-status",
]


class WebScanner(ScanModule):
    """Coordinator for web service scanning."""

    name = "Web Scan"
    slug = "web_scan"
    description = "Audit web services for security headers, sensitive files, and SSL/TLS issues"

    def __init__(
        self,
        target: str | None = None,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the WebScanner."""
        self.target = target
        self.verbose = verbose
        self.progress_callback = progress_callback
        self.semaphore = asyncio.Semaphore(10)  # Limit concurrent web requests

    async def scan(self, **kwargs: object) -> WebScanModel:
        """Execute the scan asynchronously."""
        hosts = kwargs.get("hosts", [])
        if not isinstance(hosts, list):
            hosts = []

        logger.debug(f"Web scan checking host(s) with {len(hosts)} hosts")
        all_results = []
        tasks = []

        for h in hosts:
            ip = h.get("ip", "")
            ports = h.get("tcp_ports") or h.get("tcp", [])
            for p in ports:
                port_num = p.get("port")
                service_name = (p.get("service") or p.get("name", "")).lower()

                # Identify web services by port or service name
                is_web = port_num in [80, 443, 8080, 8081, 8443] or "http" in service_name
                if is_web:
                    protocol = (
                        "https" if port_num in [443, 8443] or "https" in service_name else "http"
                    )
                    logger.info(f"Found web service on {ip}:{port_num} ({protocol})")
                    tasks.append(self._scan_service(ip, port_num, protocol))

        if tasks:
            all_results = await asyncio.gather(*tasks)

        summary = {
            "total_services": len(all_results),
            "vulnerable_headers": len([
                r for r in all_results if not r.headers.csp or not r.headers.hsts
            ]),
            "sensitive_files_found": sum(len(r.sensitive_files) for r in all_results),
            "expired_certs": len([r for r in all_results if r.tls and r.tls.expired]),
        }

        return WebScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
            version=__version__,
            results=all_results,
            summary=summary,
        )

    async def _scan_service(self, ip: str, port: int, protocol: str) -> WebScanResultModel:
        """Scan a single web service."""
        url = f"{protocol}://{ip}:{port}"
        result = WebScanResultModel(ip=ip, port=port, protocol=protocol)

        logger.info(f"Auditing web security on {ip}:{port} ({protocol.upper()})")
        logger.debug(f"Starting web scan for {url}")

        async with self.semaphore:
            try:
                async with httpx.AsyncClient(verify=False, timeout=settings.conn_timeout) as client:
                    # 1. Basic Info & Headers
                    response = await client.get(url, follow_redirects=True)
                    result.status_code = response.status_code
                    result.server = response.headers.get("Server")
                    logger.debug(
                        f"Response from {url}: {response.status_code} (Server: {result.server})"
                    )

                    # Parse Title
                    soup = BeautifulSoup(response.text, "html.parser")
                    if soup.title:
                        result.title = soup.title.string.strip() if soup.title.string else None

                    # Security Headers
                    h = response.headers
                    result.headers = SecurityHeadersModel(
                        csp="Content-Security-Policy" in h,
                        hsts="Strict-Transport-Security" in h,
                        x_frame_options="X-Frame-Options" in h,
                        x_content_type_options="X-Content-Type-Options" in h,
                        referrer_policy="Referrer-Policy" in h,
                        permissions_policy="Permissions-Policy" in h,
                    )

                    # 2. Sensitive Files
                    for path in SENSITIVE_PATHS:
                        try:
                            file_url = f"{url}/{path}"
                            file_res = await client.get(
                                file_url, timeout=2
                            )  # Use GET instead of HEAD as some servers block HEAD
                            if file_res.status_code == 200:
                                logger.warning(f"Found sensitive file on {url}: {path}")
                                result.sensitive_files.append(path)
                        except Exception as e:
                            logger.debug(f"Error checking {path} on {url}: {e}")
                            continue

                    # 3. TLS Info
                    if protocol == "https":
                        result.tls = await self._get_tls_info(ip, port)

            except Exception as e:
                result.error = str(e)
                logger.error(f"Web scan error on {url}: {e}")

        return result

    async def _get_tls_info(self, ip: str, port: int) -> Optional[TlsInfoModel]:
        """Get TLS/SSL information using the ssl module."""
        logger.debug(f"Getting TLS info for {ip}:{port}")
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            def _get_cert() -> tuple[bytes, tuple[str, str, int], str]:
                with ssl.create_connection((ip, port), timeout=settings.conn_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert(True)
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cipher, version

            cert_bin, cipher, version = await asyncio.to_thread(_get_cert)
            logger.debug(f"TLS version for {ip}:{port}: {version}")

            # Re-wrap to get decoded cert
            def _get_decoded_cert() -> dict[str, Any]:
                with ssl.create_connection((ip, port), timeout=settings.conn_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        return ssock.getpeercert()

            decoded = await asyncio.to_thread(_get_decoded_cert)

            expires_str = decoded.get("notAfter")
            expires_dt = (
                datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z") if expires_str else None
            )
            expired = expires_dt < datetime.utcnow() if expires_dt else False
            logger.debug(f"Cert for {ip}:{port} expires: {expires_str} (Expired: {expired})")

            return TlsInfoModel(
                protocol=version,
                cipher=cipher[0] if cipher else None,
                issuer=str(decoded.get("issuer")),
                expires=expires_str,
                expired=expired,
            )
        except Exception as e:
            logger.error(f"TLS info error for {ip}:{port}: {e}")
            return None
