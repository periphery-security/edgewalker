"""Guided Scanner — Handles the automatic guided security assessment workflow."""

# Standard Library
from typing import Optional

# Third Party
from loguru import logger
from rich.panel import Panel

# First Party
from edgewalker import theme, utils
from edgewalker.cli.controller import ScanController
from edgewalker.core.config import settings
from edgewalker.core.engine import AssessmentOptions, Engine, PhaseResult
from edgewalker.display import (
    build_credential_display,
    build_cve_display,
    build_port_scan_display,
    build_scan_type_panel,
)
from edgewalker.modules import port_scan
from edgewalker.modules.port_scan.models import PortScanModel

#: Human-readable lead-in shown before each module renders, keyed by module.
_PHASE_LEAD_IN: dict[str, str] = {
    "credential": "Port scan complete. Now testing for default credentials...",
    "cve": "Credential scan complete. Now checking for known vulnerabilities (CVEs)...",
    "sql": "CVE scan complete. Now auditing SQL services...",
    "web": "SQL audit complete. Now auditing web services...",
}


class GuidedScanner:
    """Handles the automatic guided security assessment workflow."""

    def __init__(self, controller: ScanController) -> None:
        """Initialize the guided scanner.

        Args:
            controller: The scan controller to use for execution.
        """
        self.controller = controller
        # Share the controller's scanner service so telemetry callbacks stay wired.
        # getattr keeps spec'd test doubles (which omit instance attributes) working.
        self.engine = Engine(getattr(controller, "scanner", None))

    async def automatic_mode(
        self,
        full_scan: Optional[bool] = None,
        target: Optional[str] = None,
        full_creds: bool = False,
        unprivileged: bool = False,
        verbose: bool = False,
    ) -> None:
        """Run the automatic guided security assessment asynchronously.

        Sequencing and gating come from the shared :class:`Engine`; this method
        only handles the CLI's interactive prompts and rendering.
        """
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

        opts = AssessmentOptions(
            target=target,
            full_scan=full_scan,
            full_creds=full_creds,
            unprivileged=unprivileged,
            verbose=verbose,
        )

        # Step 3+: Drive the canonical sequence through the engine.
        utils.console.print()
        logger.info(f"Starting {scan_type.lower()} port scan on {target}...")

        hosts_found = 0
        self.engine.progress_callback = self._progress_callback
        try:
            async for phase in self.engine.run_assessment(opts):
                if phase.module == "port" and isinstance(phase.result, PortScanModel):
                    hosts_found = len([h for h in phase.result.hosts if h.state == "up"])
                self._render_phase(phase)
        except (FileNotFoundError, ValueError) as e:
            logger.error(f"Port scan failed: {e}. Returning to mode selection.")
            utils.press_enter()
            return
        finally:
            self.engine.progress_callback = None

        if hosts_found == 0:
            logger.warning("No devices found on the network.")
            utils.press_enter()
            return

        # Final step: Show report
        utils.console.print()
        utils.console.print()
        logger.success("All scans complete! Generating your security report...")
        utils.console.print()
        self.controller.view_device_risk()

    def _progress_callback(self, event: str, data: str) -> None:
        """Render live scan progress (chiefly credential attempts) to the console."""
        if event == "service_start":
            logger.info(data)
        elif event == "cred_progress":
            utils.console.print(f"    [dim]{data}[/dim]", end="\r")
        elif event == "cred_found":
            logger.success(f"Found: {data}")

    def _render_phase(self, phase: PhaseResult) -> None:
        """Render a single completed assessment phase to the console."""
        if phase.skipped or phase.result is None:
            return

        if lead_in := _PHASE_LEAD_IN.get(phase.module):
            utils.console.print()
            utils.console.print()
            logger.info(lead_in)
            utils.console.print()

        builders = {
            "port": (build_port_scan_display, "port_scan.json", "SCAN RESULTS"),
            "credential": (build_credential_display, "password_scan.json", None),
            "cve": (build_cve_display, "cve_scan.json", None),
        }

        if phase.module in builders:
            builder, filename, header = builders[phase.module]
            if header:
                utils.print_header(header)
            for renderable in builder(phase.result.model_dump(mode="json")):
                utils.console.print(renderable)
            utils.console.print()
            logger.success(f"Results saved to: {settings.output_dir / filename}")
        else:
            # SQL and web have no dedicated console display yet; just confirm save.
            logger.success(f"Results saved to: {settings.output_dir / phase.module}_scan.json")

    async def prompt_next_scan(self) -> None:
        """After a scan completes, suggest the next step asynchronously."""
        status = utils.get_scan_status()
        WIDTH = theme.get_ui_width()

        utils.console.print()

        # All scans complete?
        if (
            status["port_scan"]
            and status["password_scan"]
            and status["cve_scan"]
            and status["sql_scan"]
            and status["web_scan"]
        ):
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
                (
                    f"    [{theme.RISK_CRITICAL}]{status['sql_vulns']}"
                    f"[/{theme.RISK_CRITICAL}] SQL vulnerabilities"
                ),
                (
                    f"    [{theme.RISK_CRITICAL}]{status['web_vulns']}"
                    f"[/{theme.RISK_CRITICAL}] Web vulnerabilities"
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

        if not status["sql_scan"] and status["port_scan"]:
            utils.console.print()
            utils.console.print(
                f"[{theme.HEADER}]{theme.ICON_ARROW} Next:[/{theme.HEADER}] "
                "SQL Audit - check database security"
            )
            choice = utils.get_input("Run now? [Y/n]", "y")
            if choice.lower() != "n":
                await self.controller.run_sql_scan()
                await self.prompt_next_scan()
            return

        if not status["web_scan"] and status["port_scan"]:
            utils.console.print()
            utils.console.print(
                f"[{theme.HEADER}]{theme.ICON_ARROW} Next:[/{theme.HEADER}] "
                "Web Audit - check web service security"
            )
            choice = utils.get_input("Run now? [Y/n]", "y")
            if choice.lower() != "n":
                await self.controller.run_web_scan()
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
