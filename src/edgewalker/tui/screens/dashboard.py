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
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, ContentSwitcher, Footer, Header, Input, RichLog, Static, Tree

# First Party
from edgewalker import theme
from edgewalker.core.config import settings, update_setting
from edgewalker.core.engine import AssessmentOptions, Engine
from edgewalker.core.findings import build_summary
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
from edgewalker.tui.widgets.navigation import NavigationPanel, ScanProgress, StatusBadge
from edgewalker.tui.widgets.overview import build_findings_view, build_overview
from edgewalker.tui.widgets.topology import TopologyWidget
from edgewalker.utils import save_results


class DashboardScreen(Screen):
    """Main dashboard for running scans and viewing results."""

    BINDINGS = [
        # Footer (Tier 1) shows only the essentials — scanning, help, back.
        # The sidebar always lists the SCAN/VIEW mnemonics with a cursor
        # highlight, and `?` opens the full keymap, so the rest stay hidden.
        Binding("s", "quick_scan", "Quick Scan", show=True),
        Binding("S", "full_scan", "Full Scan", show=True),
        Binding("question_mark", "help", "Help", show=True, key_display="?"),
        Binding("escape", "go_home", "Back", show=True),
        # SCAN / VIEW group bindings (surfaced by the sidebar + ? overlay).
        Binding("r", "run_all", "Re-run All", show=False),
        Binding("o", "overview", "Overview", show=False),
        Binding("d", "devices", "Devices", show=False),
        Binding("f", "findings", "Findings", show=False),
        Binding("l", "live_log", "Live Log", show=False),
        Binding("slash", "filter", "Filter", show=False, key_display="/"),
        Binding("ctrl+c", "copy_report", "Copy Report", show=False),
        # Hidden numeric aliases for existing muscle memory / tests.
        Binding("1", "show_report", "Risk Report", show=False),
        Binding("2", "devices", "Devices", show=False),
        Binding("3", "quick_scan", "Quick Scan", show=False),
        Binding("4", "full_scan", "Full Scan", show=False),
        Binding("5", "clear_results", "Clear All", show=False),
        Binding("6", "view_raw", "Raw Results", show=False),
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
        self._filter_query = ""

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout.

        A persistent sidebar plus a ``ContentSwitcher`` holding the four named
        views (overview, devices, findings, live-log). Only one view is mounted
        at a time; the sidebar paints a cursor highlight on the active one.
        """
        yield Header()
        with Horizontal():
            yield NavigationPanel(id="nav-panel")
            with Vertical(id="main-content"):
                yield Input(placeholder="filter — esc to clear", id="filter-input")
                with ContentSwitcher(initial="overview", id="view-switcher"):
                    yield ScrollableContainer(
                        Static(id="report-content", expand=True),
                        id="overview",
                    )
                    yield ScrollableContainer(id="devices")
                    yield ScrollableContainer(
                        Static(id="findings-content", expand=True),
                        id="findings",
                    )
                    with Vertical(id="live-log"):
                        yield ScanProgress(id="scan-header")
                        yield RichLog(highlight=True, markup=True, id="wizard-log")
                        with Horizontal(id="button-bar"):
                            yield Button("Continue", variant="primary", id="continue-btn")
        yield Footer()

    def on_mount(self) -> None:
        """Handle screen mount."""
        self.query_one("#continue-btn").display = False
        # Keep the hidden filter box out of the focus chain so it can't grab
        # the initial focus and swallow mnemonic keys (s/d/f/…).
        filter_input = self.query_one("#filter-input", Input)
        filter_input.display = False
        filter_input.can_focus = False
        if self.focused is filter_input:
            self.set_focus(None)
        self._update_permissions()

        # Replay progress log if a scan is active or was recently active.
        if self.app.scan_progress_log:
            for event, data in self.app.scan_progress_log:
                self._on_progress(event, data)

        if self._initial_report:
            self.action_overview()
        elif self._initial_topology:
            self.action_topology()
        elif self._auto_target and not self.app.is_scanning:
            # Check for security warnings and overrides first
            def proceed_with_scan() -> None:
                self._auto_step = 1
                self._next_guided_step()

            self._check_security_warnings(proceed_with_scan)
        elif self.app.scan_progress_log:
            # A scan was active when we (re)mounted — land on the live log.
            self.action_live_log()
        else:
            # Fresh start: prime the live-log idle text, land on the overview.
            self._show_welcome()
            self.action_overview()

    def _switch_view(self, view: str) -> None:
        """Activate a named view and sync the sidebar cursor highlight."""
        self.query_one("#view-switcher", ContentSwitcher).current = view
        self.query_one("#nav-panel", NavigationPanel).set_active_view(view)

    # ----------------------------------------------------- live scan state machine

    #: Phase key -> (human label, sidebar badge id).
    _PHASES = {
        "port": ("Network discovery", "#status-port"),
        "cred": ("Credential check", "#status-pwd"),
        "cve": ("Vulnerability scan", "#status-cve"),
        "sql": ("SQL audit", "#status-sql"),
        "web": ("Web audit", "#status-web"),
    }

    def _build_phase_plan(self) -> list[str]:
        """The ordered phases this assessment will run, given the toggles."""
        plan = ["port"]
        if self._run_creds:
            plan.append("cred")
        if self._run_cves:
            plan.append("cve")
        if self._run_sql:
            plan.append("sql")
        if self._run_web:
            plan.append("web")
        return plan

    def _init_scan_phases(self) -> None:
        """Mark the planned phases queued and prime the live-scan header."""
        self._phase_plan = self._build_phase_plan()
        nav = self.query_one("#nav-panel", NavigationPanel)
        for key, (_label, badge_id) in self._PHASES.items():
            nav.query_one(badge_id, StatusBadge).set_phase(
                "queued" if key in self._phase_plan else ""
            )
        self.query_one("#scan-header", ScanProgress).set_progress(
            self._auto_target, "starting…", 0, len(self._phase_plan), True
        )

    def _enter_phase(self, key: str) -> None:
        """Flip the sidebar state machine and header to the running phase."""
        plan = getattr(self, "_phase_plan", None) or self._build_phase_plan()
        nav = self.query_one("#nav-panel", NavigationPanel)
        idx = plan.index(key) if key in plan else len(plan) - 1
        for i, phase_key in enumerate(plan):
            _label, badge_id = self._PHASES[phase_key]
            state = "done" if i < idx else "running" if i == idx else "queued"
            nav.query_one(badge_id, StatusBadge).set_phase(state)
        label, _badge = self._PHASES[key]
        self.query_one("#scan-header", ScanProgress).set_progress(
            self._auto_target, label, idx + 1, len(plan), True
        )

    def _finish_scan_phases(self) -> None:
        """Stop the spinner and let the sidebar reflect the saved results."""
        self.query_one("#scan-header", ScanProgress).set_progress(
            self._auto_target, "", 0, 0, False
        )
        self.query_one("#nav-panel", NavigationPanel).update_status()

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
        self._current_report_text = ""
        log = self._get_log()
        log.clear()
        log.write(theme.gradient_text(theme.LOGO))
        log.write(f"\n  [{theme.TEXT}]Select a scan type from the menu to begin.[/]")
        log.write(
            f"\n  [{theme.MUTED_STYLE}]Quick Scan (s) is recommended for first-time users.[/]"
        )

    def _show_loading(self, message: str) -> None:
        self._current_report_text = ""
        log = self._get_log()
        log.clear()
        self._write_step_header(1, 4, "INITIALIZING")
        log.write(Text(f"\n  {message}\n", style=theme.TEXT))
        self.action_live_log()

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
                self._finish_scan_phases()
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
        if self._auto_step == 1:
            # Kicking off: lay out the sidebar state machine + header.
            self._init_scan_phases()
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
        self.query_one("#scan-header", ScanProgress).set_progress(
            self._auto_target, "", 0, 0, False
        )
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
        preflight = Engine.preflight(AssessmentOptions())
        warnings = preflight.warnings
        overrides = preflight.overrides

        if preflight.has_blockers:
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
        """Open the scan wizard pre-set for a quick scan, run on this screen."""
        self._open_scan_wizard(full_scan=False)

    def action_full_scan(self) -> None:
        """Open the scan wizard pre-set for a full scan, run on this screen."""
        self._open_scan_wizard(full_scan=True)

    def action_run_all(self) -> None:
        """Re-run a full assessment against the most recent target.

        Reuses the last scanned target (from the prior run or the saved port
        scan) and enables every module, so it is a one-key "do it all again".
        """
        if self.app.is_scanning:
            return

        target = self._auto_target
        if not target:
            port_file = settings.output_dir / "port_scan.json"
            if port_file.exists():
                with open(port_file) as f:
                    target = json.load(f).get("target", "")
        if not target:
            self.notify("No previous scan to re-run. Press s to start one.", severity="warning")
            return

        self._auto_target = target
        self._run_creds = True
        self._run_cves = True
        self._run_sql = True
        self._run_web = True
        self._auto_run = True

        def proceed() -> None:
            self._auto_step = 1
            self._next_guided_step()

        self._check_security_warnings(proceed)

    def _open_scan_wizard(self, full_scan: bool) -> None:
        """Push the config wizard; it returns its config to _begin_assessment."""
        if self.app.is_scanning:
            return
        self._from_topology = False

        # First Party
        from edgewalker.tui.screens.guided import GuidedAssessmentScreen  # noqa: PLC0415

        self.app.push_screen(GuidedAssessmentScreen(full_scan=full_scan), self._begin_assessment)

    def _begin_assessment(self, config: dict | None) -> None:
        """Run an assessment in place from wizard config (None = cancelled)."""
        if not config:
            return
        self._auto_target = config["target"]
        self._full_scan = config["full_scan"]
        self._run_creds = config["run_creds"]
        self._run_cves = config["run_cves"]
        self._run_sql = config["run_sql"]
        self._run_web = config["run_web"]
        self._full_creds = config["full_creds"]
        self._auto_run = True

        def proceed() -> None:
            self._auto_step = 1
            self._next_guided_step()

        self._check_security_warnings(proceed)

    @work(exclusive=True, group="scan")
    async def _run_guided_port_scan(self) -> None:
        """Run the guided port scan asynchronously."""
        self.app.is_scanning = True
        self.app.scan_progress_log = []  # Clear log for new scan
        self.app.scanner.progress_callback = self.app.notify_progress

        target = self._auto_target
        scan_label = "full" if self._full_scan else "quick IoT"
        self._show_loading(f"Running {scan_label} scan on {target}...")
        self._enter_phase("port")
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
        self._enter_phase("cred")

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
        self._enter_phase("cve")
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
        self._enter_phase("sql")
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
        self._enter_phase("web")
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

        # Land on the at-a-glance overview; deeper views are a keypress away.
        header = Text()
        header.append("  Assessment complete. ", style=theme.SUCCESS)
        header.append("d devices  ·  f findings  ·  l live log\n", style=theme.MUTED_STYLE)

        summary = build_summary(Engine.load_report_inputs())
        self._update_report_view(Group(header, build_overview(summary)))

        self._auto_step = 0
        self._finish_scan_phases()
        self._show_continue("Done")

    def _update_report_view(self, renderable: object) -> None:
        """Render into the overview pane and capture plain text for clipboard."""
        report_content = self.query_one("#report-content", Static)
        report_content.update(renderable)
        self._switch_view("overview")

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

    def action_overview(self) -> None:
        """Show the at-a-glance multi-panel assessment overview."""
        self._from_topology = False
        summary = build_summary(Engine.load_report_inputs())
        self._update_report_view(build_overview(summary))

    def _render_findings(self) -> None:
        """(Re)render the findings list, honouring the active filter."""
        summary = build_summary(Engine.load_report_inputs())
        self.query_one("#findings-content", Static).update(
            build_findings_view(summary, self._filter_query)
        )

    def action_findings(self) -> None:
        """Show the full prioritised findings list."""
        self._from_topology = False
        self._render_findings()
        self._switch_view("findings")

    def action_live_log(self) -> None:
        """Show the live scan log view."""
        self._switch_view("live-log")

    # ------------------------------------------------------------- filter (`/`)

    def action_filter(self) -> None:
        """Reveal the filter box for the findings / devices views."""
        view = self.query_one("#view-switcher", ContentSwitcher).current
        if view not in ("findings", "devices"):
            self.notify("Filter is available in Devices and Findings.", severity="information")
            return
        filter_input = self.query_one("#filter-input", Input)
        filter_input.can_focus = True
        filter_input.display = True
        filter_input.focus()

    async def _apply_filter(self) -> None:
        """Re-render the active view for the current filter query."""
        view = self.query_one("#view-switcher", ContentSwitcher).current
        if view == "findings":
            self._render_findings()
        elif view == "devices":
            await self._render_devices()

    async def on_input_changed(self, event: Input.Changed) -> None:
        """Live-filter the active view as the query changes."""
        if event.input.id == "filter-input":
            self._filter_query = event.value
            await self._apply_filter()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in the filter box hands focus back to the device tree."""
        if event.input.id == "filter-input":
            with contextlib.suppress(Exception):
                self.query_one("#topology-tree").focus()

    def _clear_filter(self) -> None:
        """Hide the filter box and drop the query."""
        filter_input = self.query_one("#filter-input", Input)
        filter_input.value = ""
        filter_input.display = False
        filter_input.can_focus = False
        if self.focused is filter_input:
            self.set_focus(None)
        self._filter_query = ""

    def action_show_report(self) -> None:
        """Load and display the last (detailed) security report."""
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

        renderables, _ = build_risk_report(port_data, cred_data, cve_data, sql_data, web_data)
        self._update_report_view(Group(*renderables))

    async def action_topology(self) -> None:
        """Backward-compatible alias for the devices view."""
        await self.action_devices()

    async def action_devices(self) -> None:
        """Show the network topology / device table in the dashboard."""
        self._from_topology = False
        if not (settings.output_dir / "port_scan.json").exists():
            self.notify("Port scan required first.", severity="warning")
            return
        await self._render_devices()
        self._switch_view("devices")
        with contextlib.suppress(Exception):
            self.query_one("#topology-tree").focus()

    @staticmethod
    def _host_matches(host: dict, query: str) -> bool:
        """Case-insensitive match over a host's ip / hostname / vendor."""
        haystack = f"{host.get('ip', '')} {host.get('hostname', '')} {host.get('vendor', '')}"
        return query in haystack.lower()

    async def _render_devices(self) -> None:
        """(Re)mount the topology tree, honouring the active filter.

        Does not steal focus, so it is safe to call on every filter keystroke.
        """
        inputs = Engine.load_report_inputs()
        port_data = inputs.get("port") or {}

        # Calculate risk for each host to ensure topology has latest data.
        # First Party
        from edgewalker.core.risk import RiskEngine  # noqa: PLC0415

        engine = RiskEngine(port_data, inputs["cred"], inputs["cve"], inputs["sql"], inputs["web"])
        for host in port_data.get("hosts", []):
            host["risk"] = engine.calculate_device_risk(host.get("ip"))

        query = self._filter_query.strip().lower()
        if query:
            hosts = [h for h in port_data.get("hosts", []) if self._host_matches(h, query)]
            port_data = {**port_data, "hosts": hosts}

        container = self.query_one("#devices", ScrollableContainer)
        # Remove any existing tree to avoid DuplicateIds error.
        with contextlib.suppress(Exception):
            await self.query_one("#topology-tree").remove()
        await container.mount(TopologyWidget(port_data, id="topology-tree"))

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        """Handle device selection in the topology tree."""
        device_data = event.node.data
        if not device_data or device_data.get("type") == "scanner":
            return

        # Build and show the device report (drilled in from the devices view).
        report = build_device_report(device_data)
        self._from_topology = True
        self._update_report_view(report)

        # Hint how to step back to the device list.
        self.notify("Press esc to return to Devices", timeout=3)

    def action_help(self) -> None:
        """Show the `?` keybinding cheat-sheet for this screen."""
        # First Party
        from edgewalker.tui.modals.help import HelpModal  # noqa: PLC0415

        sections = [
            ("SCAN", [("s", "Quick scan"), ("S", "Full scan"), ("r", "Re-run all")]),
            (
                "VIEW",
                [
                    ("o", "Overview"),
                    ("d", "Devices"),
                    ("f", "Findings"),
                    ("l", "Live log"),
                ],
            ),
            (
                "GENERAL",
                [
                    ("Enter", "Drill in / continue"),
                    ("/", "Filter devices / findings"),
                    ("esc", "Back / clear / cancel"),
                    ("ctrl+c", "Copy report"),
                    ("?", "This help"),
                    ("q", "Quit"),
                ],
            ),
        ]
        self.app.push_screen(HelpModal(sections))

    def action_view_raw(self) -> None:
        """Show the saved raw JSON result files (shared with the CLI)."""
        # First Party
        from edgewalker.cli.results import ResultManager  # noqa: PLC0415

        if not settings.output_dir.exists():
            self.notify("No results found. Run a scan first.", severity="warning")
            return
        files = sorted(
            settings.output_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not files:
            self.notify("No results found. Run a scan first.", severity="warning")
            return

        self._from_topology = False
        self._update_report_view(ResultManager().build_results_table(files))

    def action_clear_results(self) -> None:
        """Clear all saved results."""
        if settings.output_dir.exists():
            for f in settings.output_dir.glob("*.json"):
                f.unlink()
        self.app.scan_progress_log = []  # Clear progress log too
        self.notify("All results cleared.")
        self.query_one("#nav-panel").update_status()
        self._show_welcome()
        self.action_overview()

    async def action_go_home(self) -> None:
        """Go back to the previous view or home."""
        switcher = self.query_one("#view-switcher", ContentSwitcher)

        # 0. An open filter? Clear it first (esc unwinds one level at a time).
        if self.query_one("#filter-input", Input).display:
            self._clear_filter()
            await self._apply_filter()
            return

        # 1. A device report drilled in from the devices view → back to devices.
        if switcher.current == "overview" and self._from_topology:
            await self.action_devices()
            return

        # 2. Any non-overview view → back to the overview home.
        if switcher.current != "overview":
            self._do_go_home()
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
        """Return to the dashboard's home view (the overview).

        The dashboard is the root surface, so "home" is the at-a-glance
        overview rather than a separate screen.
        """
        self.action_overview()

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
