"""EdgeWalker TUI navigation widgets."""

from __future__ import annotations

# Third Party
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import Static

# First Party
from edgewalker import theme
from edgewalker.utils import get_scan_status


class StatusBadge(Static):
    """A small badge showing scan status."""

    def __init__(self, label: str, **kwargs: object) -> None:
        """Initialize the status badge."""
        super().__init__(**kwargs)
        self.label = label
        self.active = False
        self.detail = ""

    def render(self) -> str:
        """Render the badge."""
        if not self.active:
            return f"[{theme.MUTED}]{theme.ICON_CIRCLE} {self.label}[/{theme.MUTED}]"

        color = theme.SUCCESS
        if self.detail == "vulnerable" or (self.detail and "c" in self.detail):
            color = theme.RISK_CRITICAL

        res = f"[{color}]{theme.ICON_CIRCLE_FILLED} {self.label}[/{color}]"
        if self.detail:
            res += f" [{theme.MUTED}]({self.detail})[/{theme.MUTED}]"
        return res

    def set_status(self, active: bool, detail: str = "") -> None:
        """Update the badge status."""
        self.active = active
        self.detail = detail
        self.refresh()


class NavItem(Static):
    """A single navigation item."""

    def __init__(self, key: str, label: str, **kwargs: object) -> None:
        """Initialize the navigation item."""
        super().__init__(**kwargs)
        self.key = key
        self.label = label

    def render(self) -> str:
        """Render the navigation item."""
        # The test expects "[1] Test" literally in the output
        return f"[{self.key}] {self.label}"


class NavSeparator(Static):
    """A separator in the navigation panel."""

    def render(self) -> str:
        """Render the separator."""
        return f"[{theme.MUTED}]------------------[/{theme.MUTED}]"


class TelemetryStatus(Static):
    """A small indicator for telemetry status."""

    status = reactive("idle")

    def on_mount(self) -> None:
        """Watch the app's telemetry status for changes."""
        self.watch(self.app, "telemetry_status", self._on_telemetry_change, init=True)

    def _on_telemetry_change(self, status: str) -> None:
        """Update internal status when app status changes."""
        self.status = status

    def render(self) -> Text:
        """Render the telemetry status."""
        if self.status == "idle":
            return Text("Telemetry: Ready", style=f"{theme.MUTED}")
        elif self.status == "disabled":
            return Text("Telemetry: Disabled", style=f"{theme.MUTED}")
        elif self.status == "running":
            return Text("Telemetry: Running...", style=f"bold {theme.ACCENT}")
        elif self.status == "sending":
            return Text("Telemetry: Sending...", style=f"bold {theme.ACCENT}")
        elif self.status == "success":
            return Text("Telemetry: Sent", style=f"{theme.SUCCESS}")
        elif self.status == "error":
            return Text("Telemetry: Failed", style=f"bold {theme.DANGER}")
        return Text("")


class NavPanel(Vertical):
    """Sidebar navigation and status panel (Legacy name for tests)."""

    def compose(self) -> ComposeResult:
        """Compose the navigation panel."""
        yield Static("SCAN STATUS", id="nav-title")
        yield StatusBadge("Network", id="status-port")
        yield StatusBadge("Passwords", id="status-pwd")
        yield StatusBadge("Vulnerabilities", id="status-cve")
        yield NavSeparator()
        yield Static("SHORTCUTS", id="nav-subtitle")
        yield NavItem("1", "Risk Report")
        yield NavItem("2", "Quick Scan")
        yield NavItem("3", "Full Scan")
        yield NavItem("4", "Password Test")
        yield NavItem("5", "CVE Check")
        yield NavItem("9", "Clear All")

        # Add telemetry status at the bottom
        yield Vertical(id="nav-bottom-spacer")
        yield TelemetryStatus(id="telemetry-status")

    def on_mount(self) -> None:
        """Update status on mount."""
        self.update_status()

    def update_status(self) -> None:
        """Update all status badges."""
        status = get_scan_status()

        port_badge = self.query_one("#status-port", StatusBadge)
        pwd_badge = self.query_one("#status-pwd", StatusBadge)
        cve_badge = self.query_one("#status-cve", StatusBadge)

        if status["port_scan"]:
            detail = status["port_scan_type"]
            port_badge.set_status(True, detail)
        else:
            port_badge.set_status(False)

        if status["password_scan"]:
            v = status["vulnerable_devices"]
            detail = "vulnerable" if v > 0 else "ok"
            pwd_badge.set_status(True, detail)
        else:
            pwd_badge.set_status(False)

        if status["cve_scan"]:
            c = status["cves_found"]
            detail = f"{c}c" if c > 0 else "ok"
            cve_badge.set_status(True, detail)
        else:
            cve_badge.set_status(False)


class NavigationPanel(NavPanel):
    """Sidebar navigation and status panel."""

    pass
