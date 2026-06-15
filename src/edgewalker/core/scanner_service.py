"""EdgeWalker Scanner Service — Unified scan orchestration."""

from __future__ import annotations

# Standard Library
import asyncio
import os
from typing import Callable, Optional

# First Party
from edgewalker.core.config import settings
from edgewalker.core.demo_service import DemoService
from edgewalker.core.result_store import JsonResultStore, ResultStore
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.modules import cve_scan, password_scan, port_scan, sql_scan, web_scan
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel
from edgewalker.modules.sql_scan.models import SqlScanModel
from edgewalker.modules.web_scan.models import WebScanModel


class ScannerService:
    """Service to orchestrate scans and handle results."""

    def __init__(
        self,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        telemetry_callback: Optional[Callable[[str], None]] = None,
        telemetry: Optional[TelemetryManager] = None,
        demo_service: Optional[DemoService] = None,
        store: Optional[ResultStore] = None,
    ) -> None:
        """Initialize the scanner service.

        Telemetry, demo mode, and persistence are injected collaborators rather
        than wired up here, so the engine has no opinion about who is calling it
        or where results land. A daemon can pass its own (or no) telemetry,
        never run demo mode, and swap in a database-backed store; tests can
        inject mocks. Use :meth:`from_env` for the env-driven CLI/TUI default.

        Args:
            progress_callback: Optional callback for progress updates.
            telemetry_callback: Optional callback for telemetry status.
            telemetry: Telemetry manager to use. Defaults to a real
                ``TelemetryManager`` bound to the active settings.
            demo_service: When provided, scans return canned demo data and no
                telemetry is sent. ``None`` (the default) runs real scans.
            store: Where results are persisted and read back from. Defaults to
                :class:`JsonResultStore` (the one-off file behaviour).
        """
        self.progress_callback = progress_callback
        self.telemetry_callback = telemetry_callback
        self.telemetry = telemetry if telemetry is not None else TelemetryManager(settings)
        self.demo_service = demo_service
        self.demo_mode = demo_service is not None
        self.store = store if store is not None else JsonResultStore()

    @classmethod
    def from_env(
        cls,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        telemetry_callback: Optional[Callable[[str], None]] = None,
    ) -> "ScannerService":
        """Build a service honoring ``EW_DEMO_MODE`` — the CLI/TUI entry point.

        This is the one place the demo-mode environment variable is read, keeping
        that coupling out of the engine constructor.
        """
        demo_service = (
            DemoService(progress_callback) if os.environ.get("EW_DEMO_MODE") == "1" else None
        )
        return cls(
            progress_callback=progress_callback,
            telemetry_callback=telemetry_callback,
            demo_service=demo_service,
        )

    def _notify(self, event_type: str, message: str) -> None:
        """Notify the progress callback if it exists."""
        if self.progress_callback:
            self.progress_callback(event_type, message)

    async def _submit_telemetry(self, module: str, data: dict) -> None:
        """Submit telemetry and notify callback."""
        if self.demo_mode:
            return

        if not self.telemetry.is_telemetry_enabled():
            if self.telemetry_callback:
                self.telemetry_callback("disabled")
            return

        if self.telemetry_callback:
            self.telemetry_callback("sending")

        # Small delay to ensure "Sending..." is visible
        await asyncio.sleep(1.0)

        response = await self.telemetry.submit_scan_data(module, data)

        if self.telemetry_callback:
            if response and response.status_code == 201:
                self.telemetry_callback("success")
            else:
                self.telemetry_callback("error")

    def submit_scan_data(self, module: str, data: dict) -> None:
        """Submit scan data to telemetry (backward compatibility)."""
        if self.demo_mode:
            return

        # Fire and forget in background
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._submit_telemetry(module, data))
        except RuntimeError:
            # No loop running, use sync version
            self.telemetry.submit_scan_data_sync(module, data)

    async def perform_port_scan(
        self,
        target: str,
        full: bool = False,
        unprivileged: bool = False,
        verbose: bool = False,
    ) -> PortScanModel:
        """Perform a port scan and return results as a model asynchronously."""
        if self.demo_mode and self.demo_service:
            return await self.demo_service.perform_port_scan(target, full)

        if self.telemetry_callback:
            self.telemetry_callback("running")

        scan_label = "full" if full else "quick"
        self._notify("phase", f"Starting {scan_label} scan on {target}...")

        if full:
            results = await port_scan.full_scan(
                target=target,
                verbose=verbose,
                progress_callback=self.progress_callback,
                unprivileged=unprivileged,
            )
        else:
            results = await port_scan.quick_scan(
                target=target,
                verbose=verbose,
                progress_callback=self.progress_callback,
                unprivileged=unprivileged,
            )

        if isinstance(results, dict):
            results = PortScanModel(**results)

        # Detect gateway IP
        results.gateway_ip = port_scan.scanner.detect_gateway()

        if not results.success:
            raise ValueError(results.error or "Unknown port scan error")

        self.store.save_scan("port_scan", results)

        # Submit telemetry
        await self._submit_telemetry("port_scan", results.model_dump(mode="json"))

        return results

    async def perform_credential_scan(
        self, port_results: Optional[PortScanModel] = None, top_n: Optional[int] = 10
    ) -> PasswordScanModel:
        """Perform a credential scan based on port scan results asynchronously."""
        if self.demo_mode and self.demo_service:
            return await self.demo_service.perform_credential_scan()

        if self.telemetry_callback:
            self.telemetry_callback("running")

        self._notify("phase", "Testing for default passwords...")

        if port_results is None:
            port_results = self.store.get_latest_port_scan()
            if port_results is None:
                raise FileNotFoundError("Port scan results missing.")

        hosts = [h for h in port_results.hosts if h.state == "up"]
        if not hosts:
            self._notify("phase_done", "No active hosts found for credential testing.")
            return PasswordScanModel(results=[], summary={"vulnerable_hosts": 0})

        results = await password_scan.scan(
            hosts,
            target=port_results.target,
            top_n=top_n,
            verbose=False,
            progress_callback=self.progress_callback,
        )

        if isinstance(results, dict):
            results = PasswordScanModel(**results)

        self.store.save_scan("password_scan", results)

        # Submit telemetry
        await self._submit_telemetry("password_scan", results.model_dump(mode="json"))

        return results

    async def perform_cve_scan(self, port_results: Optional[PortScanModel] = None) -> CveScanModel:
        """Perform a CVE scan based on port scan results asynchronously."""
        if self.demo_mode and self.demo_service:
            return await self.demo_service.perform_cve_scan()

        if self.telemetry_callback:
            self.telemetry_callback("running")

        self._notify("phase", "Checking for known vulnerabilities...")

        if port_results is None:
            port_results = self.store.get_latest_port_scan()
            if port_results is None:
                raise FileNotFoundError("Port scan results missing.")

        hosts = [h for h in port_results.hosts if h.state == "up"]
        if not hosts:
            raise ValueError("No hosts found in port scan.")

        results = await cve_scan.scan(
            hosts,
            target=port_results.target,
            verbose=False,
            progress_callback=self.progress_callback,
        )

        if isinstance(results, dict):
            results = CveScanModel(**results)

        self.store.save_scan("cve_scan", results)

        # Submit telemetry
        await self._submit_telemetry("cve_scan", results.model_dump(mode="json"))

        return results

    async def perform_sql_scan(
        self,
        port_results: Optional[PortScanModel] = None,
        top_n: Optional[int] = 10,
        verbose: bool = False,
    ) -> SqlScanModel:
        """Perform a SQL scan based on port scan results asynchronously."""
        if self.telemetry_callback:
            self.telemetry_callback("running")

        self._notify("phase", "Auditing SQL services...")

        if port_results is None:
            port_results = self.store.get_latest_port_scan()
            if port_results is None:
                raise FileNotFoundError("Port scan results missing.")

        hosts = [h.model_dump(mode="json") for h in port_results.hosts if h.state == "up"]
        if not hosts:
            return SqlScanModel(results=[], summary={"vulnerable_services": 0})

        scanner = sql_scan.SqlScanner(target=port_results.target, top_n=top_n, verbose=verbose)
        results = await scanner.scan(hosts=hosts)

        self.store.save_scan("sql_scan", results, keep_snapshot=False)
        await self._submit_telemetry("sql_scan", results.model_dump(mode="json"))

        return results

    async def perform_web_scan(
        self, port_results: Optional[PortScanModel] = None, verbose: bool = False
    ) -> WebScanModel:
        """Perform a web scan based on port scan results asynchronously."""
        if self.telemetry_callback:
            self.telemetry_callback("running")

        self._notify("phase", "Auditing web services...")

        if port_results is None:
            port_results = self.store.get_latest_port_scan()
            if port_results is None:
                raise FileNotFoundError("Port scan results missing.")

        hosts = [h.model_dump(mode="json") for h in port_results.hosts if h.state == "up"]
        if not hosts:
            return WebScanModel(results=[], summary={"total_services": 0})

        scanner = web_scan.WebScanner(target=port_results.target, verbose=verbose)
        results = await scanner.scan(hosts=hosts)

        self.store.save_scan("web_scan", results, keep_snapshot=False)
        await self._submit_telemetry("web_scan", results.model_dump(mode="json"))

        return results


def submit_scan_data(module: str, data: dict) -> None:
    """Submit scan data to telemetry (backward compatibility)."""
    # This is a global function, might be called from sync context
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(TelemetryManager(settings).submit_scan_data(module, data))
    except RuntimeError:
        TelemetryManager(settings).submit_scan_data_sync(module, data)
