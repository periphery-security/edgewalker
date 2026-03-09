"""Guided Scanner — Handles the automatic guided security assessment workflow."""

# Standard Library
from typing import Optional

# Third Party
from loguru import logger
from rich.panel import Panel

# First Party
from edgewalker import theme, utils
from edgewalker.cli.controller import ScanController
from edgewalker.display import build_scan_type_panel
from edgewalker.modules import port_scan


class GuidedScanner:
    """Handles the automatic guided security assessment workflow."""

    def __init__(self, controller: ScanController) -> None:
        """Initialize the guided scanner.

        Args:
            controller: The scan controller to use for execution.
        """
        self.controller = controller

    async def automatic_mode(
        self,
        full_scan: Optional[bool] = None,
        target: Optional[str] = None,
        full_creds: bool = False,
        unprivileged: bool = False,
        verbose: bool = False,
    ) -> None:
        """Run the automatic guided security assessment asynchronously."""
        # Step 1: Choose scan type
        if full_scan is None:
            utils.clear_screen()
            utils.print_logo()
            full_scan = self._show_scan_type_selection()

        # Step 2: Get target
        scan_type = "FULL" if full_scan else "QUICK"
        if target is None:
            default_target = port_scan.get_default_target()
            utils.console.print()
            logger.info(f"A {scan_type.lower()} port scan will discover devices on your network.")
            target = utils.get_input("Target (IP/range)", default_target)

        # Step 3: Run port scan
        utils.console.print()
        logger.info(f"Starting {scan_type.lower()} port scan on {target}...")
        port_results = await self.controller.run_port_scan(
            full=full_scan, target=target, unprivileged=unprivileged, verbose=verbose
        )

        if not port_results:
            logger.error("Port scan failed. Returning to mode selection.")
            utils.press_enter()
            return

        if hasattr(port_results, "hosts"):
            hosts_up = [h for h in port_results.hosts if h.state == "up"]
        else:
            hosts_up = [h for h in port_results.get("hosts", []) if h.get("state") == "up"]

        if not hosts_up:
            logger.warning("No devices found on the network.")
            utils.press_enter()
            return

        # Step 4: Run credential scan
        utils.console.print()
        utils.console.print()
        logger.info("Port scan complete. Now testing for default credentials...")
        utils.console.print()

        top_n = None if full_creds else 10
        await self.controller.run_credential_scan(
            port_results=port_results, top_n=top_n, interactive=False
        )

        # Step 5: Run CVE scan
        utils.console.print()
        utils.console.print()
        logger.info("Credential scan complete. Now checking for known vulnerabilities (CVEs)...")
        utils.console.print()
        await self.controller.run_cve_scan(port_results=port_results)

        # Step 6: Show report
        utils.console.print()
        utils.console.print()
        logger.success("All scans complete! Generating your security report...")
        utils.console.print()
        self.controller.view_device_risk()

    async def prompt_next_scan(self) -> None:
        """After a scan completes, suggest the next step asynchronously."""
        status = utils.get_scan_status()
        WIDTH = theme.get_ui_width()

        utils.console.print()

        # All scans complete?
        if status["port_scan"] and status["password_scan"] and status["cve_scan"]:
            lines = [
                "",
                f"  [{theme.SUCCESS}]{theme.ICON_CHECK} All scans complete![/{theme.SUCCESS}]",
                "",
                f"    [bold]{status['devices_found']}[/bold] devices scanned",
                (
                    f"    [{theme.RISK_CRITICAL}]{status['vulnerable_devices']}"
                    f"[/{theme.RISK_CRITICAL}] with default credentials"
                ),
                (
                    f"    [bold {theme.WARNING}]{status['cves_found']}"
                    f"[/bold {theme.WARNING}] CVEs found"
                ),
                "",
            ]
            utils.console.print(
                Panel(
                    "\n".join(lines),
                    border_style=theme.SUCCESS,
                    box=theme.BOX_STYLE,
                    width=WIDTH,
                )
            )
            choice = utils.get_input("View your Security Report now? [Y/n]", "y")
            if choice.lower() != "n":
                self.controller.view_device_risk()
                utils.press_enter()
            return

        # Suggest next scan
        if not status["password_scan"] and status["port_scan"]:
            utils.console.print()
            utils.console.print(
                f"[{theme.HEADER}]{theme.ICON_ARROW} Next:[/{theme.HEADER}] "
                "Credential Test - check for default passwords"
            )
            choice = utils.get_input("Run now? [Y/n]", "y")
            if choice.lower() != "n":
                await self.controller.run_credential_scan()
                await self.prompt_next_scan()
            return

        if not status["cve_scan"] and status["port_scan"]:
            utils.console.print()
            utils.console.print(
                f"[{theme.HEADER}]{theme.ICON_ARROW} Next:[/{theme.HEADER}] "
                "CVE Check - find known vulnerabilities"
            )
            choice = utils.get_input("Run now? [Y/n]", "y")
            if choice.lower() != "n":
                await self.controller.run_cve_scan()
                await self.prompt_next_scan()
            return

        utils.press_enter()

    def _show_scan_type_selection(self) -> bool:
        """Show scan type selection screen. Returns True for full, False for quick."""
        utils.console.print()
        utils.console.print(build_scan_type_panel())
        utils.console.print()

        choice = utils.get_input("Select scan type", "1")

        return choice == "2"
