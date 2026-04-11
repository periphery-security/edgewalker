"""EdgeWalker TUI dashboard screen."""

from __future__ import annotations

# Standard Library
import contextlib
import io
import json
from typing import Callable

# Third Party
from rich.console import Console, Group
from rich.text import Text
from textual import events, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, RichLog, Static, Tree

# First Party
from edgewalker import theme
from edgewalker.core.config import get_active_overrides, settings, update_setting
from edgewalker.display import (
    build_credential_display,
    build_device_report,
    build_port_scan_display,
    build_risk_report,
)
from edgewalker.modules.port_scan.scanner import fix_nmap_permissions
from edgewalker.tui.modals.dialogs import (
    ConfirmModal,
    PermissionModal,
)
from edgewalker.tui.widgets.navigation import NavigationPanel
from edgewalker.tui.widgets.topology import TopologyWidget
from edgewalker.utils import save_results


class DashboardScreen(Screen):
    """Main dashboard for running scans and viewing results."""

    BINDINGS = [
        Binding("1", "show_report", "Risk Report", show=True),
        Binding("2", "topology", "Topology", show=True),
        Binding("3", "quick_scan", "Quick Scan", show=True),
        Binding("4", "full_scan", "Full Scan", show=True),
        Binding("5", "clear_results", "Clear All", show=True),
        Binding("6", "view_raw", "Raw Results", show=True),
        Binding("ctrl+c", "copy_report", "Copy Report", show=True),
        Binding("escape", "go_home", "Back", show=True),
    ]

    def __init__(
        self,
        show_report: bool = False,
        show_topology: bool = False,
        full_scan: bool = False,
        auto_target: str = "",
        run_creds: bool = False,
        run_cves: bool = False,
        run_sql: bool = False,
        run_web: bool = False,
        auto_run: bool = False,
        full_creds: bool = False,
    ) -> None:
        """Initialize the dashboard screen.

        Args:
            show_report: Whether to show the report immediately.
            show_topology: Whether to show the topology map immediately.
            full_scan: Whether to run a full scan.
            auto_target: Target for automatic scan.
            run_creds: Whether to run credential scan.
            run_cves: Whether to run CVE scan.
            run_sql: Whether to run SQL audit.
            run_web: Whether to run Web audit.
            auto_run: Whether to run automatically.
            full_creds: Whether to run full credential scan.
        """
        super().__init__()
        self._auto_step = 0
        self._auto_target = auto_target
        self._full_scan = full_scan
        self._run_creds = run_creds
        self._run_cves = run_cves
        self._run_sql = run_sql
        self._run_web = run_web
        self._auto_run = auto_run
        self._initial_report = show_report
        self._initial_topology = show_topology
        self._full_creds = full_creds
        self._current_report_text = ""
        self._from_topology = False

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield Header()
        with Horizontal():
            yield NavigationPanel(id="nav-panel")
            with Vertical(id="main-content"):
                with Container(id="log-container"):
                    yield RichLog(highlight=True, markup=True, id="wizard-log")
                    yield ScrollableContainer(
                        Static(id="report-content", expand=True),
                        id="report-container",
                    )
                    yield ScrollableContainer(id="topology-container")
                with Horizontal(id="button-bar"):
                    yield Button("Continue", variant="primary", id="continue-btn")
        yield Footer()

    def on_mount(self) -> None:
        """Handle screen mount."""
        self.query_one("#continue-btn").display = False
        self.query_one("#report-container").display = False
        self.query_one("#topology-container").display = False
        self._update_permissions()

        # Replay progress log if a scan is active or was recently active
        if self.app.scan_progress_log:
            for event, data in self.app.scan_progress_log:
                self._on_progress(event, data)

        if self._initial_report:
            self.action_show_report()
        elif self._initial_topology:
            self.action_topology()
        elif self._auto_target and not self.app.is_scanning:
            # Check for security warnings and overrides first
            def proceed_with_scan() -> None:
                self._auto_step = 1
                self._next_guided_step()

            self._check_security_warnings(proceed_with_scan)
        elif not self.app.is_scanning and not self.app.scan_progress_log:
            self._show_welcome()

    def _update_permissions(self) -> None:
        """Update UI based on nmap permissions."""
        # We'll just rely on action checks for now to avoid FrozenInstanceError
        pass

    def watch_app_has_nmap_permissions(self, has_perms: bool) -> None:
        """React to permission changes."""
        self._update_permissions()

    def _get_log(self) -> RichLog:
        return self.query_one("#wizard-log", RichLog)

    def _on_progress(self, event: str, data: str) -> None:
        """Handle progress updates from the scanner service."""
        if event == "phase":
            self._write_phase(data)
        elif event == "host_found":
            self._write_discovery(data)
        elif event == "port_found":
            self._write_port(data)
        elif event == "service_start":
            self._write_service_start(data)
        elif event == "cred_progress":
            self._write_cred_progress(data)
        elif event == "cred_found":
            self._write_cred_found(data)

    def _write_phase(self, msg: str) -> None:
        log = self._get_log()
        log.write(Text(f"\n{theme.ICON_LINE}{theme.ICON_LINE} {msg}", style=f"bold {theme.ACCENT}"))

    def _write_discovery(self, ip: str) -> None:
        log = self._get_log()
        log.write(Text(f"  {theme.ICON_PLUS} Found host: {ip}", style=theme.SUCCESS))

    def _write_port(self, detail: str) -> None:
        log = self._get_log()
        log.write(Text(f"      {theme.ICON_STEP} Open port: {detail}", style=theme.WARNING))

    def _write_service_start(self, msg: str) -> None:
        log = self._get_log()
        log.write(Text(f"  {theme.ICON_INFO} {msg}", style=theme.TEXT))

    def _write_cred_progress(self, msg: str) -> None:
        log = self._get_log()
        log.write(Text(f"      {theme.ICON_STEP} {msg}", style=theme.MUTED_STYLE))

    def _write_cred_found(self, msg: str) -> None:
        log = self._get_log()
        log.write(
            Text(f"      {theme.ICON_ALERT} VULNERABLE: {msg}", style=f"bold {theme.RISK_CRITICAL}")
        )

    def _show_welcome(self) -> None:
        self.query_one("#wizard-log").display = True
        self.query_one("#report-container").display = False
        self._current_report_text = ""
        log = self._get_log()
        log.clear()
        log.write(theme.gradient_text(theme.LOGO))
        log.write(f"\n  [{theme.TEXT}]Select a scan type from the menu to begin.[/]")
        log.write(
            f"\n  [{theme.MUTED_STYLE}]Quick Scan (3) is recommended for first-time users.[/]"
        )

    def _show_loading(self, message: str) -> None:
        self.query_one("#wizard-log").display = True
        self.query_one("#report-container").display = False
        self._current_report_text = ""
        log = self._get_log()
        log.clear()
        self._write_step_header(1, 4, "INITIALIZING")
        log.write(Text(f"\n  {message}\n", style=theme.TEXT))

    def _write_step_header(self, step: int, total: int, title: str) -> None:
        log = self._get_log()
        header = Text()
        header.append(f"\n  STEP {step}/{total}: ", style=theme.MUTED_STYLE)
        header.append(title, style=f"bold {theme.HEADER}")
        log.write(header)
        log.write(Text("  " + theme.ICON_LINE_BOLD * 40, style=theme.MUTED_STYLE))

    def _show_continue(self, label: str = "Continue") -> None:
        if self._auto_run:
            if label == "Done":
                # Final step, just reset auto_run and return
                self._auto_run = False
                return

            # Intermediate step, auto-proceed
            self.call_after_refresh(self._next_guided_step)
            return

        btn = self.query_one("#continue-btn", Button)
        btn.label = label
        btn.display = True
        btn.focus()
        log = self._get_log()
        log.write(
            Text(
                f"\n  Press [ENTER] or click below to {label}...",
                style=f"blink bold {theme.ACCENT}",
            )
        )

    def on_key(self, event: events.Key) -> None:
        """Handle manual step progression in guided mode."""
        if event.key == "enter" and not self.app.is_scanning and self._auto_step > 0:
            self._next_guided_step()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "continue-btn":
            self._next_guided_step()

    def _next_guided_step(self) -> None:
        """Progress to the next step of the guided assessment."""
        self.query_one("#continue-btn").display = False
        self._auto_step += 1
        if self._auto_step == 2:
            self._run_guided_port_scan()
        elif self._auto_step == 3:
            if self._run_creds:
                self._run_guided_cred_scan()
            else:
                self._next_guided_step()
        elif self._auto_step == 4:
            if self._run_cves:
                self._run_guided_cve_scan()
            else:
                self._next_guided_step()
        elif self._auto_step == 5:
            if self._run_sql:
                self._run_guided_sql_scan()
            else:
                self._next_guided_step()
        elif self._auto_step == 6:
            if self._run_web:
                self._run_guided_web_scan()
            else:
                self._next_guided_step()
        else:
            self._auto_step = 0
            self._auto_run = False  # Reset auto-run when finished

    def _on_scan_error(self, error: str) -> None:
        self.app.is_scanning = False
        self._auto_run = False  # Stop auto-run on error
        self.notify(error, severity="error")
        log = self._get_log()
        log.write(Text(f"\n  ERROR: {error}", style=theme.RISK_CRITICAL))
        self._show_continue("Retry")
        # If we were in guided mode, allow retry
        if self._auto_step > 0:
            self._auto_step -= 1
        else:
            # For tests that expect specific behavior
            self._auto_step = -1

    # --- Actions ---

    def _check_security_warnings(self, on_confirm: Callable[[], None]) -> None:
        """Check for security warnings and overrides, requiring confirmation.

        Args:
            on_confirm: Callback to execute if the user confirms.
        """
        warnings = settings.get_security_warnings()
        overrides = get_active_overrides()

        if warnings or overrides:
            msg_parts = []
            if warnings:
                msg_parts.append("[bold red]SECURITY WARNINGS:[/bold red]")
                for w in warnings:
                    msg_parts.append(f"• {w}")
                msg_parts.append("")

            if overrides:
                sources = ", ".join(sorted(set(overrides.values())))
                msg_parts.append(f"[bold yellow]OVERRIDES ACTIVE (via {sources}):[/bold yellow]")
                for key in sorted(overrides.keys()):
                    msg_parts.append(f"• {key}")
                msg_parts.append("")

            msg_parts.append("Do you want to proceed with the scan using these settings?")

            self.app.push_screen(
                ConfirmModal(
                    "SECURITY & CONFIGURATION CHECK",
                    "\n".join(msg_parts),
                ),
                lambda confirmed: on_confirm() if confirmed else None,
            )
        else:
            on_confirm()

    def action_quick_scan(self) -> None:
        """Start a guided quick scan."""
        if self.app.is_scanning:
            return
        self._from_topology = False
        self.query_one("#topology-container").display = False

        # First Party
        from edgewalker.tui.screens.guided import GuidedAssessmentScreen  # noqa: PLC0415

        self.app.push_screen(GuidedAssessmentScreen(full_scan=False))

    def action_full_scan(self) -> None:
        """Start a guided full scan."""
        if self.app.is_scanning:
            return
        self._from_topology = False
        self.query_one("#topology-container").display = False

        # First Party
        from edgewalker.tui.screens.guided import GuidedAssessmentScreen  # noqa: PLC0415

        self.app.push_screen(GuidedAssessmentScreen(full_scan=True))

    @work(exclusive=True, group="scan")
    async def _run_guided_port_scan(self) -> None:
        """Run the guided port scan asynchronously."""
        self.app.is_scanning = True
        self.app.scan_progress_log = []  # Clear log for new scan
        self.app.scanner.progress_callback = self.app.notify_progress

        target = self._auto_target
        scan_label = "full" if self._full_scan else "quick IoT"
        self._show_loading(f"Running {scan_label} scan on {target}...")
        try:
            results = await self.app.scanner.perform_port_scan(
                target=target, full=self._full_scan, unprivileged=settings.unprivileged
            )
            self._on_guided_port_done(results)
        except PermissionError as e:
            self._handle_permission_error(str(e))
        except Exception as e:
            self._on_scan_error(f"Port scan failed: {str(e)}")

    def _handle_permission_error(self, error: str) -> None:
        """Handle permission errors by offering to fix them or switch to unprivileged mode."""
        self.app.is_scanning = False
        self._auto_run = False

        def on_permission_choice(choice: str) -> None:
            if choice == "fix":
                # Suspend textual to allow sudo prompt in terminal
                try:
                    with self.app.suspend():
                        success = fix_nmap_permissions()
                except AttributeError:
                    # Fallback for older Textual versions if necessary
                    success = fix_nmap_permissions()

                if success:
                    self.notify("Permissions fixed! Retrying scan...")
                    self._run_guided_port_scan()
                else:
                    self.notify("Failed to fix permissions.", severity="error")
                    self._on_scan_error(error)
            elif choice == "unprivileged":
                update_setting("unprivileged", True)
                self.notify("Switched to Unprivileged Mode. Retrying scan...")
                self._run_guided_port_scan()
            else:
                self._on_scan_error(error)

        self.app.push_screen(PermissionModal(), on_permission_choice)

    def _on_guided_port_done(self, results: object) -> None:
        """Handle completion of the guided port scan."""
        self.app.is_scanning = False
        log = self._get_log()
        log.clear()

        # Handle both model and dict for backward compatibility during transition
        if hasattr(results, "model_dump"):
            results_dict = results.model_dump(mode="json")
        else:
            results_dict = results

        hosts = [h for h in results_dict.get("hosts", []) if h.get("state", "up") == "up"]
        total_ports = sum(len(h.get("tcp") or h.get("tcp_ports", [])) for h in hosts)

        self._write_step_header(2, 4, "DEVICES FOUND")

        target_info = Text()
        target_info.append("\n  Target: ", style=theme.MUTED_STYLE)
        target_info.append(f"{self._auto_target}\n", style=f"bold {theme.ACCENT}")
        log.write(target_info)

        summary = Text()
        summary.append("\n  We found ", style=theme.TEXT)
        summary.append(f"{len(hosts)} device(s)", style=f"bold {theme.SUCCESS}")
        summary.append(" on your network\n  with ", style=theme.TEXT)
        summary.append(f"{total_ports} open port(s)", style=f"bold {theme.WARNING}")
        summary.append(" between them.\n", style=theme.TEXT)
        log.write(summary)

        renderables = build_port_scan_display(results_dict)
        for r in renderables:
            log.write(r)

        explanation = Text()
        explanation.append(
            "\n  Open ports are like unlocked doors — they're not\n"
            "  always bad, but attackers look for them.\n\n",
            style=theme.TEXT,
        )
        log.write(explanation)

        if self._run_creds:
            next_step = Text()
            next_step.append(
                f"  {theme.ICON_ARROW} NEXT: PASSWORD CHECK\n",
                style=f"bold {theme.WARNING}",
            )
            next_step.append(
                "  We'll test if any of these devices still use\n"
                "  factory-default passwords (like admin/admin).\n"
                "  This is the #1 way IoT devices get hacked.\n",
                style=theme.TEXT,
            )
            log.write(next_step)
        elif self._run_cves:
            next_step = Text()
            next_step.append(
                f"  {theme.ICON_ARROW} NEXT: CVE CHECK\n",
                style=f"bold {theme.WARNING}",
            )
            next_step.append(
                "  We'll check if any software running on your\n"
                "  devices has known security holes (CVEs).\n",
                style=theme.TEXT,
            )
            log.write(next_step)

        if not hosts:
            log.write(
                Text(
                    "\n  No devices responded. Try a different target.\n",
                    style=theme.WARNING,
                )
            )
            self._show_continue("Done")
            self._auto_step = 3
        else:
            self._show_continue()

    @work(exclusive=True, group="scan")
    async def _run_guided_cred_scan(self) -> None:
        """Run the guided credential scan asynchronously."""
        self.app.is_scanning = True
        self.app.scanner.progress_callback = self.app.notify_progress

        depth_label = "thorough" if self._full_creds else "quick"
        self._show_loading(f"Testing for default passwords ({depth_label})...")

        top_n = None if self._full_creds else 10
        try:
            results = await self.app.scanner.perform_credential_scan(top_n=top_n)
            self._on_guided_cred_done(results)
        except Exception as e:
            self._on_scan_error(f"Credential scan failed: {str(e)}")

    def _on_guided_cred_done(self, results: object) -> None:
        """Handle completion of the guided credential scan."""
        self.app.is_scanning = False
        log = self._get_log()
        log.clear()

        if hasattr(results, "model_dump"):
            results_dict = results.model_dump(mode="json")
        else:
            results_dict = results

        # Build the full report with all available data
        with open(settings.output_dir / "port_scan.json") as f:
            final_port_data = json.load(f)

        cve_data = {}
        cve_file = settings.output_dir / "cve_scan.json"
        if cve_file.exists():
            with open(cve_file) as f:
                cve_data = json.load(f)

        sql_data = {}
        sql_file = settings.output_dir / "sql_scan.json"
        if sql_file.exists():
            with open(sql_file) as f:
                sql_data = json.load(f)

        web_data = {}
        web_file = settings.output_dir / "web_scan.json"
        if web_file.exists():
            with open(web_file) as f:
                web_data = json.load(f)

        renderables, report_data = build_risk_report(
            final_port_data, results_dict, cve_data, sql_data, web_data
        )
        if report_data:
            save_results(report_data, "security_report.json")

        vuln = results_dict.get("summary", {}).get("vulnerable_hosts", 0)
        self._write_step_header(3, 4, "CREDENTIAL CHECK")

        if vuln > 0:
            msg = Text()
            msg.append("\n  ", style="")
            msg.append(f"{vuln} device(s)", style=theme.RISK_CRITICAL)
            msg.append(
                " have default passwords that anyone\n"
                "  could guess. This is the #1 way IoT devices get\n"
                "  hacked.\n",
                style=theme.TEXT,
            )
        else:
            msg = Text()
            msg.append(
                "\n  Good news — no default passwords found.\n"
                "  Your devices aren't using factory credentials.\n",
                style=theme.SUCCESS,
            )
        log.write(msg)
        renderables = build_credential_display(results_dict)
        for r in renderables:
            log.write(r)

        if self._run_cves:
            explanation = Text()
            explanation.append(
                "\n  Next, we'll check if any software running on your\n"
                "  devices has known security holes (CVEs).\n",
                style=theme.MUTED_STYLE,
            )
            log.write(explanation)

        self._show_continue()

    @work(exclusive=True, group="scan")
    async def _run_guided_cve_scan(self) -> None:
        """Run the guided CVE scan asynchronously."""
        self.app.is_scanning = True
        self.app.scanner.progress_callback = self.app.notify_progress
        self._show_loading("Checking for known vulnerabilities...")
        try:
            results = await self.app.scanner.perform_cve_scan()
            self.app.is_scanning = False

            if hasattr(results, "model_dump"):
                results_dict = results.model_dump(mode="json")
            else:
                results_dict = results

            # Build the full report with all available data
            with open(settings.output_dir / "port_scan.json") as f:
                final_port_data = json.load(f)

            cred_data = {}
            pwd_file = settings.output_dir / "password_scan.json"
            if pwd_file.exists():
                with open(pwd_file) as f:
                    cred_data = json.load(f)

            sql_data = {}
            sql_file = settings.output_dir / "sql_scan.json"
            if sql_file.exists():
                with open(sql_file) as f:
                    sql_data = json.load(f)

            web_data = {}
            web_file = settings.output_dir / "web_scan.json"
            if web_file.exists():
                with open(web_file) as f:
                    web_data = json.load(f)

            renderables, report_data = build_risk_report(
                final_port_data, cred_data, results_dict, sql_data, web_data
            )
            if report_data:
                save_results(report_data, "security_report.json")

            self._on_guided_cve_done(results_dict, renderables)
        except Exception as e:
            self._on_scan_error(f"CVE scan failed: {str(e)}")

    @work(exclusive=True, group="scan")
    async def _run_guided_sql_scan(self) -> None:
        """Run the guided SQL scan asynchronously."""
        self.app.is_scanning = True
        self.app.scanner.progress_callback = self.app.notify_progress
        self._show_loading("Auditing SQL services...")
        try:
            results = await self.app.scanner.perform_sql_scan()
            self._on_guided_sql_done(results)
        except Exception as e:
            self._on_scan_error(f"SQL scan failed: {str(e)}")

    def _on_guided_sql_done(self, results: object) -> None:
        """Handle completion of the guided SQL scan."""
        self.app.is_scanning = False
        log = self._get_log()
        log.clear()

        if hasattr(results, "model_dump"):
            results_dict = results.model_dump(mode="json")
        else:
            results_dict = results

        # Build the full report with all available data
        with open(settings.output_dir / "port_scan.json") as f:
            final_port_data = json.load(f)

        cred_data = {}
        pwd_file = settings.output_dir / "password_scan.json"
        if pwd_file.exists():
            with open(pwd_file) as f:
                cred_data = json.load(f)

        cve_data = {}
        cve_file = settings.output_dir / "cve_scan.json"
        if cve_file.exists():
            with open(cve_file) as f:
                cve_data = json.load(f)

        web_data = {}
        web_file = settings.output_dir / "web_scan.json"
        if web_file.exists():
            with open(web_file) as f:
                web_data = json.load(f)

        renderables, report_data = build_risk_report(
            final_port_data, cred_data, cve_data, results_dict, web_data
        )
        if report_data:
            save_results(report_data, "security_report.json")

        vuln = results_dict.get("summary", {}).get("vulnerable_services", 0)
        self._write_step_header(5, 6, "SQL SECURITY AUDIT")

        if vuln > 0:
            msg = Text()
            msg.append("\n  ", style="")
            msg.append(f"{vuln} SQL service(s)", style=theme.RISK_CRITICAL)
            msg.append(
                " have security issues or default credentials.\n",
                style=theme.TEXT,
            )
        else:
            msg = Text()
            msg.append(
                "\n  No SQL security issues found on discovered services.\n",
                style=theme.SUCCESS,
            )
        log.write(msg)

        # We could add a build_sql_display here if needed
        self._show_continue()

    @work(exclusive=True, group="scan")
    async def _run_guided_web_scan(self) -> None:
        """Run the guided web scan asynchronously."""
        self.app.is_scanning = True
        self.app.scanner.progress_callback = self.app.notify_progress
        self._show_loading("Auditing web services...")
        try:
            results = await self.app.scanner.perform_web_scan()
            self.app.is_scanning = False

            if hasattr(results, "model_dump"):
                results_dict = results.model_dump(mode="json")
            else:
                results_dict = results

            # Build the full report
            with open(settings.output_dir / "port_scan.json") as f:
                final_port_data = json.load(f)

            cred_data = {}
            pwd_file = settings.output_dir / "password_scan.json"
            if pwd_file.exists():
                with open(pwd_file) as f:
                    cred_data = json.load(f)

            cve_data = {}
            cve_file = settings.output_dir / "cve_scan.json"
            if cve_file.exists():
                with open(cve_file) as f:
                    cve_data = json.load(f)

            sql_data = {}
            sql_file = settings.output_dir / "sql_scan.json"
            if sql_file.exists():
                with open(sql_file) as f:
                    sql_data = json.load(f)

            renderables, report_data = build_risk_report(
                final_port_data, cred_data, cve_data, sql_data, results_dict
            )
            if report_data:
                save_results(report_data, "security_report.json")

            self._on_guided_web_done(results_dict, renderables)
        except Exception as e:
            self._on_scan_error(f"Web scan failed: {str(e)}")

    def _on_guided_web_done(self, results: dict, report_renderables: list) -> None:
        """Handle completion of the guided web scan."""
        self.app.is_scanning = False

        # Build a Group of renderables for the Static widget
        header = Text()
        header.append("\n  STEP 6/6: SECURITY ASSESSMENT\n", style=f"bold {theme.HEADER}")
        header.append("  " + theme.ICON_LINE_BOLD * 40 + "\n", style=theme.MUTED_STYLE)

        footer = Text(
            "\n  Assessment complete. Use [1] to view the full report.\n", style=theme.SUCCESS
        )

        # Combine all into a Group
        all_renderables = [header] + report_renderables + [footer]
        self._update_report_view(Group(*all_renderables))

        self._auto_step = 0
        self.query_one("#nav-panel").update_status()
        self._show_continue("Done")

    def _update_report_view(self, renderable: object) -> None:
        """Update the selectable report view and capture plain text for clipboard."""
        self.query_one("#wizard-log").display = False
        self.query_one("#report-container").display = True

        report_content = self.query_one("#report-content", Static)
        report_content.update(renderable)

        # Capture plain text for clipboard
        # Use a high width to avoid wrapping issues in the copy
        console = Console(file=io.StringIO(), force_terminal=False, width=120)
        console.print(renderable)
        self._current_report_text = console.file.getvalue()

    def action_copy_report(self) -> None:
        """Copy the current report text to the system clipboard."""
        if not self._current_report_text:
            self.notify("No report data to copy.", severity="warning")
            return

        try:
            self.app.copy_to_clipboard(self._current_report_text)
            self.notify("Report copied to clipboard!", severity="info")
        except Exception as e:
            self.notify(f"Failed to copy: {e}", severity="error")

    def _on_guided_cve_done(self, results: dict, report_renderables: list) -> None:
        """Handle completion of the guided CVE scan."""
        self.app.is_scanning = False
        self.query_one("#nav-panel").update_status()
        self._show_continue()

    def action_show_report(self) -> None:
        """Load and display the last security report."""
        self._from_topology = False
        self.query_one("#topology-container").display = False
        port_file = settings.output_dir / "port_scan.json"
        if not port_file.exists():
            self.notify("Port scan required first.", severity="warning")
            return

        with open(port_file) as f:
            port_data = json.load(f)

        cred_data = {}
        pwd_file = settings.output_dir / "password_scan.json"
        if pwd_file.exists():
            with open(pwd_file) as f:
                cred_data = json.load(f)

        cve_data = {}
        cve_file = settings.output_dir / "cve_scan.json"
        if cve_file.exists():
            with open(cve_file) as f:
                cve_data = json.load(f)

        sql_data = {}
        sql_file = settings.output_dir / "sql_scan.json"
        if sql_file.exists():
            with open(sql_file) as f:
                sql_data = json.load(f)

        web_data = {}
        web_file = settings.output_dir / "web_scan.json"
        if web_file.exists():
            with open(web_file) as f:
                web_data = json.load(f)

        renderables, _ = build_risk_report(port_data, cred_data, cve_data, sql_data, web_data)
        self._update_report_view(Group(*renderables))

    async def action_topology(self) -> None:
        """Show the network topology map in the dashboard."""
        self._from_topology = False
        port_file = settings.output_dir / "port_scan.json"
        if not port_file.exists():
            self.notify("Port scan required first.", severity="warning")
            return

        with open(port_file) as f:
            port_data = json.load(f)

        cred_data = {}
        pwd_file = settings.output_dir / "password_scan.json"
        if pwd_file.exists():
            with open(pwd_file) as f:
                cred_data = json.load(f)

        cve_data = {}
        cve_file = settings.output_dir / "cve_scan.json"
        if cve_file.exists():
            with open(cve_file) as f:
                cve_data = json.load(f)

        sql_data = {}
        sql_file = settings.output_dir / "sql_scan.json"
        if sql_file.exists():
            with open(sql_file) as f:
                sql_data = json.load(f)

        web_data = {}
        web_file = settings.output_dir / "web_scan.json"
        if web_file.exists():
            with open(web_file) as f:
                web_data = json.load(f)

        # Calculate risk for each host to ensure topology has latest data
        # First Party
        from edgewalker.core.risk import RiskEngine  # noqa: PLC0415

        engine = RiskEngine(port_data, cred_data, cve_data, sql_data, web_data)
        for host in port_data.get("hosts", []):
            host["risk"] = engine.calculate_device_risk(host.get("ip"))

        self.query_one("#wizard-log").display = False
        self.query_one("#report-container").display = False

        container = self.query_one("#topology-container")
        container.display = True

        # Check if tree already exists to avoid DuplicateIds error
        with contextlib.suppress(Exception):
            existing_tree = self.query_one("#topology-tree")
            await existing_tree.remove()
        await container.mount(TopologyWidget(port_data, id="topology-tree"))
        self.query_one("#topology-tree").focus()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle device selection in the topology tree."""
        device_data = event.node.data
        if not device_data or device_data.get("type") == "scanner":
            return

        # Build and show the device report
        report = build_device_report(device_data)
        self._from_topology = True
        self.query_one("#topology-container").display = False
        self._update_report_view(report)

        # Add a temporary binding to go back to topology
        self.notify("Press [6] to return to Topology", timeout=3)

    def action_view_raw(self) -> None:
        """Show raw JSON results."""
        self.notify("Raw results view not yet implemented in TUI.", severity="info")

    def action_clear_results(self) -> None:
        """Clear all saved results."""
        self.query_one("#topology-container").display = False
        if settings.output_dir.exists():
            for f in settings.output_dir.glob("*.json"):
                f.unlink()
        self.app.scan_progress_log = []  # Clear progress log too
        self.notify("All results cleared.")
        self.query_one("#nav-panel").update_status()
        self._show_welcome()

    async def action_go_home(self) -> None:
        """Go back to the previous view or home."""
        # 1. If showing a device report from topology, go back to topology
        if self.query_one("#report-container").display and self._from_topology:
            await self.action_topology()
            return

        # 2. If showing topology, go back to main report or welcome
        if self.query_one("#topology-container").display:
            # First Party
            from edgewalker.utils import has_port_scan  # noqa: PLC0415

            if has_port_scan():
                self.action_show_report()
            else:
                self._show_welcome()
            return

        # 3. Otherwise, go home (with scan confirmation if needed)
        if self.app.is_scanning:

            def check_confirm(confirmed: bool) -> None:
                if confirmed:
                    self.app.is_scanning = False  # Stop tracking
                    self._do_go_home()

            self.call_after_refresh(
                lambda: self.app.push_screen(
                    ConfirmModal(
                        "STOP SCAN?",
                        (
                            "A scan remains active. Navigating home will "
                            "cancel the current assessment."
                        ),
                    ),
                    check_confirm,
                )
            )
            return

        self._do_go_home()

    def _do_go_home(self) -> None:
        """Pop screens until HomeScreen is the active screen."""
        # First Party
        from edgewalker.tui.screens.home import HomeScreen  # noqa: PLC0415

        # Pop screens until HomeScreen is the active screen
        while len(self.app.screen_stack) > 0 and not isinstance(self.app.screen, HomeScreen):
            self.app.pop_screen()

    def action_quit_app(self) -> None:
        """Exit the application."""
        # This is now handled by the global action_quit_app in EdgeWalkerApp
        self.app.action_quit_app()

    # --- Backward Compatibility for Tests ---
    def _start_guided_flow(self) -> None:
        self.action_quick_scan()

    def action_back(self) -> None:
        """Alias for go_home for backward compatibility."""
        self.app.call_next(self.action_go_home)

    def _write_progress(self, event: str, data: str) -> None:
        self._on_progress(event, data)

    def _on_continue_pressed(self) -> None:
        self._next_guided_step()

    def _make_progress_callback(self) -> Callable[[str, str], None]:
        return self._on_progress
