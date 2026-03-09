"""Scan Controller — Handles execution of security scans and result display."""

# Standard Library
import json
from typing import Optional

# Third Party
from loguru import logger

# First Party
from edgewalker import theme, utils
from edgewalker.core.config import settings
from edgewalker.core.scanner_service import ScannerService
from edgewalker.display import (
    build_credential_display,
    build_cve_display,
    build_port_scan_display,
    build_risk_report,
)
from edgewalker.modules import port_scan
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel


class ScanController:
    """Handles execution of security scans and result display."""

    def __init__(self, scanner_service: Optional[ScannerService] = None) -> None:
        """Initialize the scan controller.

        Args:
            scanner_service: Optional service for scan orchestration.
        """
        self.scanner = scanner_service or ScannerService()

    async def run_port_scan(
        self,
        full: bool = False,
        target: str = None,
        unprivileged: bool = False,
        verbose: bool = False,
    ) -> Optional[PortScanModel]:
        """Run port scan and display results asynchronously."""
        scan_type = "FULL" if full else "QUICK"
        utils.print_header(f"{scan_type} PORT SCAN")

        if not target:
            default_target = port_scan.get_default_target()
            target = utils.get_input("Target (IP/range)", default_target)

        utils.console.print()
        logger.info(f"Starting {scan_type.lower()} scan on {target}")

        try:
            with utils.console.status(f"[bold green]Scanning {target}..."):
                results = await self.scanner.perform_port_scan(
                    target=target, full=full, unprivileged=unprivileged, verbose=verbose
                )
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            logger.error("Make sure nmap is installed and you have sudo privileges.")
            return None

        # Display results
        utils.print_header("SCAN RESULTS")
        results_dict = results.model_dump(mode="json")
        for renderable in build_port_scan_display(results_dict):
            utils.console.print(renderable)

        utils.console.print()
        logger.success(f"Results saved to: {settings.output_dir / 'port_scan.json'}")

        return results

    async def run_credential_scan(
        self,
        port_results: Optional[PortScanModel] = None,
        top_n: Optional[int] = 10,
        interactive: bool = True,
        target: Optional[str] = None,  # Added back for backward compatibility
    ) -> Optional[PasswordScanModel]:
        """Run credential scan and display results asynchronously."""
        utils.print_header("CREDENTIAL SCAN")

        if port_results is None:
            port_file = settings.output_dir / "port_scan.json"
            if port_file.exists():
                with open(port_file) as f:
                    port_data = json.load(f)
                # Ensure required fields exist for Pydantic
                if "hosts" not in port_data:
                    port_data["hosts"] = []
                if "all_ports" not in port_data:
                    port_data["all_ports"] = False
                if "version_scan" not in port_data:
                    port_data["version_scan"] = False
                port_results = PortScanModel(**port_data)
            elif target:
                # Create a dummy port results with just the target host
                port_results = PortScanModel(
                    hosts=[{"ip": target, "mac": "00:00:00:00:00:00", "tcp": []}]
                )
            else:
                logger.error("No port scan results found. Run a port scan first.")
                return None

        if isinstance(port_results, dict):
            port_results = PortScanModel(**port_results)

        if interactive:
            # Ask for credential count
            utils.console.print()
            logger.info("We have ~170 default credentials per service (SSH, FTP, Telnet)")
            logger.info("Testing all takes longer. Top 10 catches most common defaults.")
            utils.console.print()
            top_n_str = utils.get_input(
                "How many to test per service? (10=fast, 'all'=thorough)", str(top_n)
            )

            if top_n_str.lower() == "all":
                top_n = None  # Test all
                logger.info("Testing ALL credentials (this may take a while)")
            else:
                try:
                    top_n = int(top_n_str)
                    logger.info(f"Testing top {top_n} credentials per service")
                except ValueError:
                    top_n = 10
                    logger.info(f"Testing top {top_n} credentials per service")
            utils.console.print()
        else:
            if top_n:
                logger.info(f"Testing top {top_n} credentials per service")
            else:
                logger.info("Testing ALL credentials (this may take a while)")

        def progress_callback(event: str, data: str) -> None:
            if event == "service_start":
                logger.info(data)
            elif event == "cred_progress":
                # Use console.print for progress to avoid log spam but show activity
                utils.console.print(f"    [dim]{data}[/dim]", end="\r")
            elif event == "cred_found":
                logger.success(f"Found: {data}")

        # Update scanner with callback
        self.scanner.progress_callback = progress_callback
        try:
            results = await self.scanner.perform_credential_scan(
                port_results=port_results, top_n=top_n
            )
        except (FileNotFoundError, ValueError) as e:
            logger.error(str(e))
            return None
        finally:
            self.scanner.progress_callback = None

        # Display results
        utils.console.print()
        results_dict = results.model_dump(mode="json")
        for renderable in build_credential_display(results_dict):
            utils.console.print(renderable)

        utils.console.print()
        logger.success(f"Results saved to: {settings.output_dir / 'password_scan.json'}")

        return results

    async def run_cve_scan(
        self, port_results: Optional[PortScanModel] = None
    ) -> Optional[CveScanModel]:
        """Run CVE scan and display results asynchronously."""
        utils.print_header("CVE VULNERABILITY SCAN")

        if port_results is None:
            port_file = settings.output_dir / "port_scan.json"
            if port_file.exists():
                with open(port_file) as f:
                    port_data = json.load(f)
                # Ensure required fields exist for Pydantic
                if "hosts" not in port_data:
                    port_data["hosts"] = []
                if "all_ports" not in port_data:
                    port_data["all_ports"] = False
                if "version_scan" not in port_data:
                    port_data["version_scan"] = False
                port_results = PortScanModel(**port_data)
            else:
                logger.error("No port scan results found. Run a port scan first.")
                return None

        if isinstance(port_results, dict):
            port_results = PortScanModel(**port_results)

        logger.info("Checking software versions against NVD database")
        logger.warning("This may take a while due to API rate limits")
        utils.console.print()

        try:
            results = await self.scanner.perform_cve_scan(port_results=port_results)
        except Exception as e:
            logger.error(f"CVE scan failed: {str(e)}")
            return None

        # Display results
        utils.console.print()
        results_dict = results.model_dump(mode="json")
        for renderable in build_cve_display(results_dict):
            utils.console.print(renderable)

        utils.console.print()
        logger.success(f"Results saved to: {settings.output_dir / 'cve_scan.json'}")

        return results

    def view_device_risk(self) -> None:
        """View device risk assessment report."""
        utils.clear_screen()
        utils.console.print()

        # Load all available data
        port_scan_file = settings.output_dir / "port_scan.json"
        password_scan_file = settings.output_dir / "password_scan.json"
        cve_scan_file = settings.output_dir / "cve_scan.json"

        if not port_scan_file.exists():
            logger.error("No port scan results found. Run a port scan first.")
            return

        with open(port_scan_file) as f:
            port_data = json.load(f)

        cred_data = {}
        if password_scan_file.exists():
            with open(password_scan_file) as f:
                cred_data = json.load(f)

        cve_data = {}
        if cve_scan_file.exists():
            with open(cve_scan_file) as f:
                cve_data = json.load(f)

        renderables, report_data = build_risk_report(port_data, cred_data, cve_data)

        for renderable in renderables:
            utils.console.print(renderable)

        utils.console.print()

        if report_data:
            report_path = utils.save_results(report_data, "security_report.json")
            details_msg = (
                f"  [{theme.MUTED_STYLE}]{theme.ICON_ARROW} "
                f"Full details: {report_path}[/{theme.MUTED_STYLE}]"
            )
            utils.console.print(details_msg)
