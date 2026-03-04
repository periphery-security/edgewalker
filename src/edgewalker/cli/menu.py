"""Interactive Menu — Handles the interactive menu interface."""

# Third Party
from loguru import logger
from rich import box
from rich.panel import Panel
from rich.table import Table

# First Party
from edgewalker import theme, utils
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner
from edgewalker.cli.results import ResultManager
from edgewalker.core.config import settings, update_setting
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.display import build_mode_panel, build_status_panel


class InteractiveMenu:
    """Handles the interactive menu interface."""

    def __init__(
        self,
        controller: ScanController,
        result_manager: ResultManager,
        guided_scanner: GuidedScanner,
    ) -> None:
        """Initialize the interactive menu.

        Args:
            controller: The scan controller to use for execution.
            result_manager: The result manager to use for data handling.
            guided_scanner: The guided scanner to use for automatic mode.
        """
        self.controller = controller
        self.result_manager = result_manager
        self.guided_scanner = guided_scanner
        self.telemetry = TelemetryManager(settings)

    async def run(self) -> None:
        """Run the interactive menu interface asynchronously."""
        # Show opt-in prompt on first run
        utils.clear_screen()
        utils.print_logo()
        utils.ensure_telemetry_choice()

        self.result_manager.check_previous_results()

        while True:
            # Mode selection
            utils.clear_screen()
            utils.print_logo()
            mode = self._show_mode_selection()

            if mode == "exit":
                utils.console.print()
                logger.info("Goodbye!")
                utils.console.print()
                return

            if mode == "auto":
                await self.guided_scanner.automatic_mode()
                utils.press_enter()
                continue

            if mode == "report":
                if (settings.output_dir / "security_report.json").exists():
                    self.controller.view_device_risk()
                    utils.press_enter()
                else:
                    utils.console.print()
                    logger.warning("No report found. Run a scan first.")
                    utils.press_enter()
                continue

            if mode == "settings":
                self._settings_menu()
                continue

            # Manual mode
            await self._manual_mode()

    def _settings_menu(self) -> None:
        """Show the settings menu."""
        while True:
            utils.clear_screen()
            utils.print_logo()
            utils.console.print()

            table = Table(box=box.SIMPLE)
            table.add_column("Option", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("[1] Telemetry Enabled", str(settings.telemetry_enabled))
            table.add_row("[2] NVD API Key", settings.nvd_api_key or "Not set")
            table.add_row("[0] Back", "")

            utils.console.print(
                Panel(
                    table,
                    title=f"[{theme.HEADER}]EDGEWALKER SETTINGS[/{theme.HEADER}]",
                    border_style=theme.ACCENT,
                    box=theme.BOX_STYLE,
                    width=theme.get_ui_width(),
                )
            )
            utils.console.print()

            choice = utils.get_input("Select option", "0")

            if choice == "1":
                new_val = not settings.telemetry_enabled
                update_setting("telemetry_enabled", new_val)
                logger.info(f"Telemetry {'enabled' if new_val else 'disabled'}.")
                utils.press_enter()
            elif choice == "2":
                key = utils.get_input("Enter NVD API Key (leave blank to clear)")
                update_setting("nvd_api_key", key if key else None)
                logger.info("NVD API Key updated.")
                utils.press_enter()
            elif choice == "0":
                break

    def _show_mode_selection(self) -> str:
        """Show mode selection screen. Returns 'auto', 'manual', 'report', or 'exit'."""
        utils.console.print(
            f"  [{theme.TEXT}]Vendors promise their devices are secure by\n"
            f"  design. We don't buy it. EdgeWalker scans your\n"
            f"  network for open ports, default credentials, and\n"
            f"  known vulnerabilities so you don't have to trust\n"
            f"  the label on the box.[/{theme.TEXT}]"
        )
        utils.console.print()

        utils.console.print()
        utils.console.print(build_mode_panel())
        utils.console.print()

        choice = utils.get_input("Select mode", "1")

        if choice == "0":
            return "exit"
        if choice == "2":
            return "manual"
        if choice == "3":
            return "report"
        if choice == "4":
            return "settings"
        return "auto"

    async def _manual_mode(self) -> None:
        """Run the manual menu loop asynchronously."""
        while True:
            utils.clear_screen()
            utils.print_logo()
            utils.console.print()
            utils.console.print(build_status_panel())
            utils.console.print()

            choice = utils.get_input("Select option", "0")

            if choice == "1":
                if not utils.has_port_scan():
                    self._warn_port_scan_required("view their risk assessment")
                else:
                    self.controller.view_device_risk()
                    utils.press_enter()

            elif choice == "2":
                await self.controller.run_port_scan(full=False)
                await self.guided_scanner.prompt_next_scan()

            elif choice == "3":
                utils.console.print()
                logger.warning("Full scan checks ALL 65535 ports on each device.")
                logger.info("This provides the most thorough results but takes longer.")
                logger.info("Expect ~15 min for a typical home network.")
                utils.console.print()
                confirm = utils.get_input("Start full scan? [y/N]", "n")
                if confirm.lower() == "y":
                    await self.controller.run_port_scan(full=True)
                    await self.guided_scanner.prompt_next_scan()
                else:
                    logger.info("Cancelled.")
                    utils.press_enter()

            elif choice == "4":
                if not utils.has_port_scan():
                    self._warn_port_scan_required("test credentials against them")
                else:
                    await self.controller.run_credential_scan()
                    await self.guided_scanner.prompt_next_scan()

            elif choice == "5":
                if not utils.has_port_scan():
                    self._warn_port_scan_required("check them for CVEs")
                else:
                    await self.controller.run_cve_scan()
                    await self.guided_scanner.prompt_next_scan()

            elif choice == "8":
                if not utils.has_any_results():
                    utils.console.print()
                    logger.warning("No results yet!")
                    logger.info("Run a scan first to generate results.")
                    utils.press_enter()
                else:
                    self.result_manager.view_results()
                    utils.press_enter()

            elif choice == "9":
                if not utils.has_any_results():
                    utils.console.print()
                    logger.warning("No results to clear!")
                    utils.press_enter()
                else:
                    self.result_manager.clear_results()
                    utils.press_enter()

            elif choice == "0":
                break

            else:
                logger.error("Invalid option")
                utils.press_enter()

    def _warn_port_scan_required(self, action: str) -> None:
        """Show a warning that a port scan is required."""
        utils.console.print()
        logger.warning("Port scan required first!")
        logger.info("Run a Quick or Full Port Scan to discover devices/services,")
        logger.info(f"then you can {action}.")
        utils.press_enter()
