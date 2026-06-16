"""About EdgeWalker — company, project, and version info.

The durable home for brand/company information, reachable on demand from the
command palette (progressive disclosure) rather than a blocking landing page.
"""

from __future__ import annotations

# Third Party
from textual import events
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

# First Party
from edgewalker import __version__, theme
from edgewalker.core.config import settings

_CONTRIBUTORS = "Steven Marks · Dr Lina Anaya · Travis Pell · Adam Massey"

_BLURB = (
    "EdgeWalker audits your home network for open ports, default credentials, "
    "and known vulnerabilities — so you can verify a device's security instead "
    "of trusting the label on the box."
)


class AboutModal(ModalScreen):
    """A dismissible panel describing EdgeWalker and Periphery."""

    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        """Compose the about panel."""
        with Vertical(classes="modal-container", id="about-container"):
            yield Static(theme.gradient_text(theme.LOGO), id="about-logo")
            yield Static(f"[{theme.ACCENT} italic]{theme.TAGLINE}[/]", id="about-tagline")
            yield Static(f"[{theme.TEXT}]{_BLURB}[/]", id="about-blurb")
            yield Static(
                f"[{theme.MUTED}]Version[/]   [{theme.TEXT}]{__version__}[/]\n"
                f"[{theme.MUTED}]Device[/]    [{theme.TEXT}]{settings.device_id}[/]\n"
                f"[{theme.MUTED}]By[/]        [{theme.TEXT}]Periphery — periphery.security[/]\n"
                f"[{theme.MUTED}]Team[/]      [{theme.TEXT}]{_CONTRIBUTORS}[/]",
                id="about-meta",
            )
            yield Button("Close", variant="primary", id="about-close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Close on the Close button."""
        if event.button.id == "about-close":
            self.dismiss()

    def action_dismiss(self, result: object = None) -> None:
        """Close the modal (Esc binding)."""
        self.dismiss()

    def on_key(self, event: events.Key) -> None:
        """Close on Enter as well."""
        if event.key == "enter":
            self.dismiss()
