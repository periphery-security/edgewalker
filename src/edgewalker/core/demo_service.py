"""EdgeWalker Demo Service — Mock scan orchestration for demos."""

from __future__ import annotations

# Standard Library
import asyncio
import uuid
from typing import Callable, Optional

# First Party
from edgewalker import __version__
from edgewalker.modules.cve_scan.models import CveModel, CveScanModel, CveScanResultModel
from edgewalker.modules.password_scan.models import (
    CredentialsModel,
    PasswordScanModel,
    PasswordScanResultModel,
    ServiceEnum,
    StatusEnum,
)
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort
from edgewalker.utils import get_device_id, save_results


class DemoService:
    """Service to simulate scans with mock data for demonstrations."""

    def __init__(self, progress_callback: Optional[Callable[[str, str], None]] = None) -> None:
        """Initialize the demo service.

        Args:
            progress_callback: Optional callback for progress updates.
        """
        self.progress_callback = progress_callback

    def _notify(self, event_type: str, message: str) -> None:
        """Notify the progress callback if it exists."""
        if self.progress_callback:
            self.progress_callback(event_type, message)

    async def perform_port_scan(self, target: str, full: bool = False) -> PortScanModel:
        """Simulate a port scan for demo purposes."""
        self._notify("phase", f"Starting demo scan on {target}...")
        await asyncio.sleep(0.8)

        self._notify("host_found", "192.168.1.1")
        await asyncio.sleep(0.8)
        self._notify("port_found", "192.168.1.1:80/http")

        self._notify("host_found", "192.168.1.15")
        await asyncio.sleep(0.8)
        self._notify("port_found", "192.168.1.15:22/ssh")
        self._notify("port_found", "192.168.1.15:554/rtsp")
        await asyncio.sleep(1.0)

        results = PortScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id("local"),
            version=__version__,
            module="port_scan",
            module_version="0.1.0",
            target=target,
            scan_type="demo",
            is_demo=True,
            hosts=[
                Host(
                    ip="192.168.1.1",
                    mac="00:11:22:33:44:55",
                    hostname="router.local",
                    vendor="TP-Link",
                    os=["Embedded Linux"],
                    tcp=[
                        TcpPort(
                            port=80, name="http", product_name="Apache", product_version="2.4.41"
                        )
                    ],
                ),
                Host(
                    ip="192.168.1.15",
                    mac="AA:BB:CC:DD:EE:FF",
                    hostname="smart-cam.local",
                    vendor="Hikvision",
                    os=["Embedded Linux"],
                    tcp=[
                        TcpPort(
                            port=22, name="ssh", product_name="Dropbear", product_version="2019.78"
                        ),
                        TcpPort(
                            port=554,
                            name="rtsp",
                            product_name="Hikvision RTSP",
                            product_version="1.0",
                        ),
                    ],
                ),
            ],
            hosts_responded=2,
            hosts_with_ports=2,
        )

        results_dict = results.model_dump(mode="json")
        save_results(results_dict, "port_scan.json")
        return results

    async def perform_credential_scan(self) -> PasswordScanModel:
        """Simulate a credential scan for demo purposes."""
        self._notify("phase", "Testing for default passwords...")
        await asyncio.sleep(1.5)

        self._notify("service_start", "192.168.1.15 SSH:22 -- testing 10 credentials")
        await asyncio.sleep(1.2)
        self._notify("cred_found", "192.168.1.15 SSH:22 -- admin:12345")
        await asyncio.sleep(1.0)

        results = PasswordScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id("local"),
            version=__version__,
            module="password_scan",
            module_version="0.1.0",
            is_demo=True,
            results=[
                PasswordScanResultModel(
                    ip="192.168.1.15",
                    port=22,
                    service=ServiceEnum.ssh,
                    login_attempt=StatusEnum.successful,
                    credentials=CredentialsModel(user="admin", password="12345"),
                    tested_count=1,
                )
            ],
            summary={
                "total_hosts": 1,
                "vulnerable_hosts": 1,
                "services_tested": 1,
                "credentials_found": 1,
            },
        )

        results_dict = results.model_dump(mode="json")
        save_results(results_dict, "password_scan.json")
        return results

    async def perform_cve_scan(self) -> CveScanModel:
        """Simulate a CVE scan for demo purposes."""
        self._notify("phase", "Checking for known vulnerabilities...")
        await asyncio.sleep(1.5)

        results = CveScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id("local"),
            version=__version__,
            module="cve_scan",
            module_version="0.1.0",
            is_demo=True,
            results=[
                CveScanResultModel(
                    ip="192.168.1.1",
                    port=80,
                    service="http",
                    product="Apache",
                    version="2.4.41",
                    cves=[
                        CveModel(
                            id="CVE-2021-41773",
                            description=(
                                "Path traversal and file disclosure vulnerability "
                                "in Apache HTTP Server 2.4.49."
                            ),
                            severity="CRITICAL",
                            score=9.8,
                        )
                    ],
                )
            ],
            summary={
                "total_services": 1,
                "services_with_version": 1,
                "services_without_version": 0,
                "services_with_cves": 1,
                "total_cves": 1,
                "critical_cves": 1,
                "high_cves": 0,
                "skipped_no_version": 0,
            },
        )

        results_dict = results.model_dump(mode="json")
        save_results(results_dict, "cve_scan.json")
        return results
