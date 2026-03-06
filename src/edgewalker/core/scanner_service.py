"""EdgeWalker Scanner Service — Unified scan orchestration."""

from __future__ import annotations

# Standard Library
import asyncio
import json
import os
from typing import Callable, Optional

# First Party
from edgewalker.core.config import settings
from edgewalker.core.demo_service import DemoService
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.modules import cve_scan, password_scan, port_scan
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel
from edgewalker.utils import save_results


class ScannerService:
    """Service to orchestrate scans and handle results."""

    def __init__(
        self,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        telemetry_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Initialize the scanner service.

        Args:
            progress_callback: Optional callback for progress updates.
            telemetry_callback: Optional callback for telemetry status.
        """
        self.progress_callback = progress_callback
        self.telemetry_callback = telemetry_callback
        self.telemetry = TelemetryManager(settings)
        self.demo_mode = os.environ.get("EW_DEMO_MODE") == "1"
        self.demo_service = DemoService(progress_callback) if self.demo_mode else None

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

    async def perform_port_scan(self, target: str, full: bool = False, unprivileged: bool = False, verbose: bool = False) -> PortScanModel:
        """Perform a port scan and return results as a model asynchronously."""
        if self.demo_mode and self.demo_service:
            return await self.demo_service.perform_port_scan(target, full)

        if self.telemetry_callback:
            self.telemetry_callback("running")

        scan_label = "full" if full else "quick"
        self._notify("phase", f"Starting {scan_label} scan on {target}...")

        if full:
            results = await port_scan.full_scan(
                target=target, verbose=verbose, progress_callback=self.progress_callback, unprivileged=unprivileged
            )
        else:
            results = await port_scan.quick_scan(
                target=target, verbose=verbose, progress_callback=self.progress_callback, unprivileged=unprivileged
            )

        if isinstance(results, dict):
            results = PortScanModel(**results)

        if not results.success:
            raise ValueError(results.error or "Unknown port scan error")

        results_dict = results.model_dump(mode="json")
        filename = f"port_scan_{results.device_id}.json"
        save_results(results_dict, filename)
        # Also save as port_scan.json for backward compatibility/latest
        save_results(results_dict, "port_scan.json")

        # Submit telemetry
        await self._submit_telemetry("port_scan", results_dict)

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
            port_file = settings.output_dir / "port_scan.json"
            if not port_file.exists():
                raise FileNotFoundError("Port scan results missing.")
            with open(port_file) as f:
                port_data = json.load(f)
            port_results = PortScanModel(**port_data)

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

        results_dict = results.model_dump(mode="json")
        filename = f"password_scan_{results.device_id}.json"
        save_results(results_dict, filename)
        # Also save as password_scan.json for backward compatibility/latest
        save_results(results_dict, "password_scan.json")

        # Submit telemetry
        await self._submit_telemetry("password_scan", results_dict)

        return results

    async def perform_cve_scan(self, port_results: Optional[PortScanModel] = None) -> CveScanModel:
        """Perform a CVE scan based on port scan results asynchronously."""
        if self.demo_mode and self.demo_service:
            return await self.demo_service.perform_cve_scan()

        if self.telemetry_callback:
            self.telemetry_callback("running")

        self._notify("phase", "Checking for known vulnerabilities...")

        if port_results is None:
            port_file = settings.output_dir / "port_scan.json"
            if not port_file.exists():
                raise FileNotFoundError("Port scan results missing.")
            with open(port_file) as f:
                port_data = json.load(f)
            port_results = PortScanModel(**port_data)

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

        results_dict = results.model_dump(mode="json")
        filename = f"cve_scan_{results.device_id}.json"
        save_results(results_dict, filename)
        # Also save as cve_scan.json for backward compatibility/latest
        save_results(results_dict, "cve_scan.json")

        # Submit telemetry
        await self._submit_telemetry("cve_scan", results_dict)

        return results


def submit_scan_data(module: str, data: dict) -> None:
    """Submit scan data to telemetry (backward compatibility)."""
    # This is a global function, might be called from sync context
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(TelemetryManager(settings).submit_scan_data(module, data))
    except RuntimeError:
        TelemetryManager(settings).submit_scan_data_sync(module, data)
