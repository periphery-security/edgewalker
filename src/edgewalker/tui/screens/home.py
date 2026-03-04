"""EdgeWalker TUI home screen."""

from __future__ import annotations

# Third Party
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

# First Party
from edgewalker import theme
from edgewalker.utils import has_port_scan


class Logo(Static):
    """A widget that renders the EdgeWalker ASCII logo with a theme-aware gradient."""

    def render(self) -> Text:
        """Render the logo with current theme colors."""
        return theme.gradient_text(theme.LOGO)


class HomeScreen(Screen):
    """The landing screen for the application."""

    BINDINGS = [
        Binding("1", "start_guided", "Start Guided Scan", show=True),
        Binding("2", "dashboard", "Dashboard", show=True),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def compose(self) -> ComposeResult:
        """Compose the home screen layout."""
        yield Header()
        with Vertical(id="home-container"):
            yield Logo(id="home-logo")
            yield Static(theme.TAGLINE, id="home-tagline")
            yield Static("", id="home-spacer")
            yield Static(
                f"[{theme.TEXT}]Vendors promise their devices are secure by design.\n"
                "We don't buy it. EdgeWalker scans your network for\n"
                "open ports, default credentials, and known vulnerabilities\n"
                "so you don't have to trust the label on the box.[/]",
                id="home-desc",
            )
            yield Static("", id="home-spacer-2")

            with Horizontal(id="home-buttons"):
                yield Button("Start Guided Assessment", variant="success", id="btn-scan")
                yield Button("Go to Dashboard", variant="default", id="btn-dashboard")

            yield Static(
                f"[{theme.ACCENT}]Press [1] for Guided Assessment or [2] for Dashboard[/]",
                id="home-prompt",
            )

            yield Static(
                f"[{theme.MUTED}]HACKATHON TEAM: Adam Massey, Steven Marks, "
                "Dr Lina Anaya, Travis Pell[/]",
                id="home-contributors",
            )
        yield Footer()

    def on_mount(self) -> None:
        """Initialize the screen."""
        self._update_permissions()

    def _update_permissions(self) -> None:
        """Update UI based on nmap permissions."""
        has_perms = self.app.has_nmap_permissions
        btn_scan = self.query_one("#btn-scan", Button)
        btn_scan.disabled = not has_perms

    def watch_app_has_nmap_permissions(self, has_perms: bool) -> None:
        """React to permission changes."""
        self._update_permissions()

    def action_start_guided(self) -> None:
        """Start the guided scan workflow."""
        # First Party
        from edgewalker.tui.screens.guided import GuidedAssessmentScreen  # noqa: PLC0415

        if self.app.has_nmap_permissions:
            self.app.push_screen(GuidedAssessmentScreen())
        else:
            self.notify("Port scanning requires elevated privileges.", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-scan":
            self.action_start_guided()
        elif event.button.id == "btn-dashboard":
            self.action_dashboard()

    def action_dashboard(self) -> None:
        """Go to the dashboard."""
        # First Party
        from edgewalker.tui.screens.dashboard import DashboardScreen  # noqa: PLC0415

        if has_port_scan():
            self.app.push_screen(DashboardScreen(show_report=True))
        else:
            self.app.push_screen(DashboardScreen())

    def action_quit_app(self) -> None:
        """Exit the application."""
        self.app.action_quit_app()

    # --- Backward Compatibility for Tests ---
    def action_select_report(self) -> None:
        """Select a report (backward compatibility)."""
        self.action_dashboard()

    def on_screen_resume(self) -> None:
        """Handle screen resume."""
        pass
