"""EdgeWalker TUI scan configuration screen.

A single, focused configuration panel (depth, target, optional tests) rather
than a multi-step wizard — per the TUI design system: keep related options
visible together, let the user tab through and start, no needless paging.
It returns its config to the dashboard, which runs the assessment in place.
"""

from __future__ import annotations

# Standard Library
from typing import Any

# Third Party
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    RadioButton,
    RadioSet,
    Static,
)

# First Party
from edgewalker.modules import port_scan


class GuidedAssessmentScreen(Screen):
    """Single-panel scan configuration that returns its config on start."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("q", "quit_app", "Quit", show=False),
    ]

    def __init__(self, full_scan: bool = False) -> None:
        """Initialize the configuration screen.

        Args:
            full_scan: Whether to pre-select a full scan.
        """
        super().__init__()
        self.config: dict[str, Any] = {
            "full_scan": full_scan,
            "target": port_scan.get_default_target(),
            "run_creds": True,
            "full_creds": False,
            "run_cves": True,
            "run_sql": True,
            "run_web": True,
        }

    def compose(self) -> ComposeResult:
        """Compose the single configuration panel."""
        yield Header()
        with Vertical(id="wizard-outer"):
            with Vertical(id="scan-config", classes="modal-container"):
                yield Static("CONFIGURE SCAN", classes="modal-title")

                yield Static("SCAN DEPTH", classes="wizard-section")
                yield RadioSet(
                    RadioButton(
                        "Quick — common IoT ports (~30s)",
                        value=not self.config["full_scan"],
                        id="radio-quick",
                    ),
                    RadioButton(
                        "Full — all 65535 ports (~15m)",
                        value=self.config["full_scan"],
                        id="radio-full",
                    ),
                    id="wizard-depth-radio",
                )

                yield Static("TARGET", classes="wizard-section")
                yield Input(value=self.config["target"], id="wizard-target-input")

                yield Static("ADDITIONAL TESTS", classes="wizard-section")
                yield Checkbox("Default passwords", value=self.config["run_creds"], id="chk-creds")
                yield Checkbox(
                    "Thorough password scan (all credentials)",
                    value=self.config["full_creds"],
                    id="chk-full-creds",
                )
                yield Checkbox(
                    "Known vulnerabilities (CVEs)", value=self.config["run_cves"], id="chk-cves"
                )
                yield Checkbox(
                    "SQL services (MySQL, Redis, …)", value=self.config["run_sql"], id="chk-sql"
                )
                yield Checkbox(
                    "Web services (headers, TLS, …)", value=self.config["run_web"], id="chk-web"
                )

                with Horizontal(classes="modal-buttons"):
                    yield Button("Cancel", id="btn-cancel")
                    yield Button("Start scan", variant="success", id="btn-start")
        yield Footer()

    def on_mount(self) -> None:
        """Focus the primary action."""
        self.query_one("#btn-start", Button).focus()

    def _collect(self) -> dict[str, Any]:
        """Read every control into the config dict and return it."""
        self.config["full_scan"] = self.query_one("#radio-full", RadioButton).value
        self.config["target"] = self.query_one("#wizard-target-input", Input).value
        self.config["run_creds"] = self.query_one("#chk-creds", Checkbox).value
        self.config["full_creds"] = self.query_one("#chk-full-creds", Checkbox).value
        self.config["run_cves"] = self.query_one("#chk-cves", Checkbox).value
        self.config["run_sql"] = self.query_one("#chk-sql", Checkbox).value
        self.config["run_web"] = self.query_one("#chk-web", Checkbox).value
        return self.config

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Start / Cancel."""
        if event.button.id == "btn-start":
            self.dismiss(self._collect())
        elif event.button.id == "btn-cancel":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in the target field starts the scan."""
        if event.input.id == "wizard-target-input":
            self.dismiss(self._collect())

    def action_cancel(self) -> None:
        """Cancel configuration and return to the dashboard."""
        self.dismiss(None)

    def action_quit_app(self) -> None:
        """Exit the application."""
        self.app.action_quit_app()
