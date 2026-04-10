"""EdgeWalker TUI guided assessment screen."""

from __future__ import annotations

# Standard Library
from typing import Any

# Third Party
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, RadioButton, RadioSet, Static

# First Party
from edgewalker import theme
from edgewalker.modules import port_scan
from edgewalker.tui.screens.dashboard import DashboardScreen


class GuidedAssessmentScreen(Screen):
    """A step-by-step wizard for configuring a security assessment."""

    BINDINGS = [
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(self) -> None:
        """Initialize the guided assessment screen."""
        super().__init__()
        self.step = 1
        self.config: dict[str, Any] = {
            "full_scan": False,
            "target": port_scan.get_default_target(),
            "run_creds": True,
            "full_creds": False,
            "run_cves": True,
            "run_sql": True,
            "run_web": True,
        }

    def compose(self) -> ComposeResult:
        """Compose the wizard layout."""
        yield Header()
        with Vertical(id="wizard-outer"):
            with Container(id="wizard-container", classes="modal-container"):
                yield Static("", id="wizard-title", classes="modal-title")
                yield Vertical(id="wizard-content", classes="modal-body")
                with Horizontal(id="wizard-buttons", classes="modal-buttons"):
                    yield Button("Back", id="btn-back", variant="default")
                    yield Button("Next", id="btn-next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize the first step."""
        self._update_step()

    def _update_step(self) -> None:
        """Update the UI for the current step."""
        title = self.query_one("#wizard-title", Static)
        content = self.query_one("#wizard-content", Vertical)
        btn_next = self.query_one("#btn-next", Button)
        btn_back = self.query_one("#btn-back", Button)

        content.remove_children()
        btn_back.label = "Back" if self.step > 1 else "Cancel"
        btn_next.label = "Next"
        btn_next.variant = "primary"

        if self.step == 1:
            title.update("STEP 1: SCAN DEPTH")
            content.mount(
                Static(
                    "Choose how deep you want to scan your network.\n\n"
                    "[bold]Quick Scan[/]: 28 common IoT ports (~30s)\n"
                    "[bold]Full Scan[/]: All 65535 ports (~15m)\n",
                    classes="wizard-text",
                )
            )

            # Pass children to constructor to avoid MountError
            radio_set = RadioSet(
                RadioButton("Quick Scan", value=not self.config["full_scan"], id="radio-quick"),
                RadioButton("Full Scan", value=self.config["full_scan"], id="radio-full"),
                id="wizard-depth-radio",
            )
            content.mount(radio_set)

        elif self.step == 2:
            title.update("STEP 2: SCAN TARGET")
            content.mount(
                Static(
                    "Enter the IP address or CIDR range to scan.\n"
                    "Default is your local network subnet.\n",
                    classes="wizard-text",
                ),
                Input(value=self.config["target"], id="wizard-target-input"),
            )
            self.call_after_refresh(lambda: self.query_one("#wizard-target-input").focus())

        elif self.step == 3:
            title.update("STEP 3: ADDITIONAL TESTS")
            content.mount(
                Static(
                    "Select which additional security tests to perform:\n", classes="wizard-text"
                ),
                Checkbox(
                    "Test for default passwords", value=self.config["run_creds"], id="chk-creds"
                ),
                Checkbox(
                    f"  {theme.ICON_STEP} Thorough Password Scan (all credentials)",
                    value=self.config["full_creds"],
                    id="chk-full-creds",
                ),
                Checkbox(
                    "Check for known vulnerabilities (CVEs)",
                    value=self.config["run_cves"],
                    id="chk-cves",
                ),
                Checkbox(
                    "Audit SQL services (MySQL, Redis, etc.)",
                    value=self.config["run_sql"],
                    id="chk-sql",
                ),
                Checkbox(
                    "Audit web services (Headers, SSL, etc.)",
                    value=self.config["run_web"],
                    id="chk-web",
                ),
            )

        elif self.step == 4:
            title.update("READY TO RUN")
            mode = "Full" if self.config["full_scan"] else "Quick"
            cred_mode = "Thorough" if self.config["full_creds"] else "Quick"

            # Build summary strings to avoid long lines
            pass_test = f"[green]Yes[/] ({cred_mode})" if self.config["run_creds"] else "[red]No[/]"
            cve_test = "[green]Yes[/]" if self.config["run_cves"] else "[red]No[/]"
            sql_test = "[green]Yes[/]" if self.config["run_sql"] else "[red]No[/]"
            web_test = "[green]Yes[/]" if self.config["run_web"] else "[red]No[/]"

            summary = (
                f"Assessment Summary:\n\n"
                f"  {theme.ICON_BULLET} Mode: [bold]{mode} Scan[/]\n"
                f"  {theme.ICON_BULLET} Target: [bold]{self.config['target']}[/]\n"
                f"  {theme.ICON_BULLET} Password Test: {pass_test}\n"
                f"  {theme.ICON_BULLET} CVE Check: {cve_test}\n"
                f"  {theme.ICON_BULLET} SQL Audit: {sql_test}\n"
                f"  {theme.ICON_BULLET} Web Audit: {web_test}\n\n"
                "Click 'RUN' to begin the assessment."
            )
            content.mount(Static(summary, classes="wizard-text"))
            btn_next.label = "RUN"
            btn_next.variant = "success"

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle radio set changes."""
        self.config["full_scan"] = event.pressed.id == "radio-full"

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle enter key in target input."""
        if event.input.id == "wizard-target-input":
            self.config["target"] = event.value
            self.step += 1
            self._update_step()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        if event.button.id == "btn-back":
            if self.step > 1:
                self.step -= 1
                self._update_step()
            else:
                self.app.pop_screen()
        elif event.button.id == "btn-next":
            if self.step == 1:
                # RadioSet already updated config
                pass
            elif self.step == 2:
                self.config["target"] = self.query_one("#wizard-target-input", Input).value
            elif self.step == 3:
                self.config["run_creds"] = self.query_one("#chk-creds", Checkbox).value
                self.config["full_creds"] = self.query_one("#chk-full-creds", Checkbox).value
                self.config["run_cves"] = self.query_one("#chk-cves", Checkbox).value
                self.config["run_sql"] = self.query_one("#chk-sql", Checkbox).value
                self.config["run_web"] = self.query_one("#chk-web", Checkbox).value

            if self.step < 4:
                self.step += 1
                self._update_step()
            else:
                # Start the scan!
                self._start_assessment()

    def _start_assessment(self) -> None:
        """Transition to the dashboard and start the scan."""
        self.app.push_screen(
            DashboardScreen(
                full_scan=self.config["full_scan"],
                auto_target=self.config["target"],
                run_creds=self.config["run_creds"],
                run_cves=self.config["run_cves"],
                run_sql=self.config["run_sql"],
                run_web=self.config["run_web"],
                auto_run=True,
                full_creds=self.config["full_creds"],
            )
        )

    def action_quit_app(self) -> None:
        """Exit the application."""
        self.app.action_quit_app()
