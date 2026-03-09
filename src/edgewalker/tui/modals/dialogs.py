"""EdgeWalker TUI modal dialogs."""

from __future__ import annotations

# Standard Library
import sys

# Third Party
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

# First Party
from edgewalker.modules import port_scan


class TelemetryModal(ModalScreen[bool]):
    """Modal dialog for telemetry opt-in."""

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Container(id="optin-dialog", classes="modal-container"):
            yield Static("HELP SECURE IOT DEVICES", id="optin-title", classes="modal-title")
            yield Static(
                "EdgeWalker can share anonymous scan results with Periphery's "
                "research team. This helps us identify emerging IoT "
                "vulnerabilities and improve our default credential database.",
                id="optin-text",
                classes="modal-body",
            )
            yield Static(
                "We NEVER share your IP address, hostnames, or MAC addresses. "
                "All data is anonymized before leaving your machine.",
                id="optin-privacy",
                classes="modal-body",
            )
            with Horizontal(id="optin-buttons", classes="modal-buttons"):
                yield Button("No thanks", variant="error", id="optin-no")
                yield Button("I'll help!", variant="success", id="optin-yes")

    def on_mount(self) -> None:
        """Focus the opt-in button on mount."""
        self.query_one("#optin-yes").focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "optin-yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


class ScanTypeModal(ModalScreen[bool]):
    """Modal dialog for scan type selection."""

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Container(id="scantype-dialog", classes="modal-container"):
            yield Static("CHOOSE SCAN DEPTH", id="scantype-title", classes="modal-title")
            yield Static(
                "Quick Scan: 28 common IoT ports (~30s)\nFull Scan: All 65535 ports (~15m)",
                id="scantype-text",
                classes="modal-body",
            )
            with Horizontal(id="scantype-buttons", classes="modal-buttons"):
                yield Button("Quick Scan", variant="primary", id="scan-quick")
                yield Button("Full Scan", variant="default", id="scan-full")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "scan-full":
            self.dismiss(True)
        else:
            self.dismiss(False)


class CredScanTypeModal(ModalScreen[bool]):
    """Modal dialog for credential scan depth selection."""

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Container(id="credtype-dialog", classes="modal-container"):
            yield Static("CREDENTIAL SCAN DEPTH", id="credtype-title", classes="modal-title")
            yield Static(
                "Quick Check: Top 10 common credentials (~10s)\n"
                "Full Check: All ~170 credentials (~2m)",
                id="credtype-text",
                classes="modal-body",
            )
            with Horizontal(id="credtype-buttons", classes="modal-buttons"):
                yield Button("Quick Check", variant="primary", id="cred-quick")
                yield Button("Full Check", variant="default", id="cred-full")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "cred-full":
            self.dismiss(True)
        else:
            self.dismiss(False)


class TargetInputModal(ModalScreen[str]):
    """Modal dialog for target input."""

    def __init__(self, default: str | None = None, **kwargs: object) -> None:
        """Initialize the target input modal.

        Args:
            default: Default target value.
            kwargs: Additional arguments for the screen.
        """
        super().__init__(**kwargs)
        self.default_value = default or port_scan.get_default_target()

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Container(id="target-dialog", classes="modal-container"):
            yield Static("SCAN TARGET", id="target-title", classes="modal-title")
            yield Static(
                "Enter the IP address or CIDR range you want to scan. "
                "By default, we'll scan your local network.",
                id="target-text",
                classes="modal-body",
            )
            yield Input(
                value=self.default_value,
                placeholder="e.g. 192.168.1.0/24",
                id="target-input",
            )
            with Horizontal(id="target-buttons", classes="modal-buttons"):
                yield Button("Cancel", variant="error", id="target-cancel")
                yield Button("Start Scan", variant="success", id="target-start")

    def on_mount(self) -> None:
        """Focus the input on mount."""
        self.query_one("#target-input").focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "target-start":
            target = self.query_one("#target-input", Input).value
            self.dismiss(target)
        else:
            self.app.pop_screen()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle enter key in input."""
        self.dismiss(event.value)


class ConfirmModal(ModalScreen[bool]):
    """Generic confirmation modal."""

    def __init__(self, title: str, message: str, **kwargs: object) -> None:
        """Initialize the confirmation modal.

        Args:
            title: Modal title.
            message: Modal message.
            kwargs: Additional arguments for the screen.
        """
        super().__init__(**kwargs)
        self.title_text = title
        self.message_text = message

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Container(classes="modal-container"):
            yield Static(self.title_text, classes="modal-title")
            yield Static(self.message_text, classes="modal-body")
            with Horizontal(classes="modal-buttons"):
                yield Button("Cancel", variant="default", id="confirm-no")
                yield Button("Confirm", variant="error", id="confirm-yes")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "confirm-yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


class PermissionModal(ModalScreen[str]):
    """Modal dialog for fixing nmap permissions or switching to unprivileged mode."""

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        is_linux = sys.platform.startswith("linux")

        with Container(id="permission-dialog", classes="modal-container"):
            yield Static("NMAP PERMISSIONS REQUIRED", id="permission-title", classes="modal-title")

            msg = (
                "Nmap requires elevated privileges for raw socket access "
                "(SYN scans and OS detection).\n\n"
            )
            if is_linux:
                msg += (
                    "Would you like to apply a one-time permission fix? "
                    "This will allow EdgeWalker to run scans without sudo.\n\n"
                    "[bold]Requires sudo password.[/]"
                )
            else:
                msg += (
                    "On macOS, you must run with 'sudo edgewalker' for full scans, "
                    "or use Unprivileged Mode (TCP Connect scans)."
                )

            yield Static(msg, id="permission-text", classes="modal-body")

            with Horizontal(id="permission-buttons", classes="modal-buttons"):
                yield Button("Cancel", variant="default", id="perm-no")
                if is_linux:
                    yield Button("Apply Fix", variant="success", id="perm-fix")
                yield Button("Unprivileged Mode", variant="primary", id="perm-unprivileged")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "perm-fix":
            self.dismiss("fix")
        elif event.button.id == "perm-unprivileged":
            self.dismiss("unprivileged")
        else:
            self.dismiss("cancel")
