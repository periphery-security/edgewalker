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
    """A single navigation item.

    Renders ``[key] label`` with the mnemonic key emphasised. When the item
    represents a dashboard view it carries the ContentSwitcher ``view`` name so
    the panel can paint a cursor highlight on the active view.
    """

    def __init__(self, key: str, label: str, view: str | None = None, **kwargs: object) -> None:
        """Initialize the navigation item."""
        super().__init__(**kwargs)
        self.key = key
        self.label = label
        self.view = view
        self.active = False
        self.add_class("nav-link")

    def render(self) -> Text:
        """Render the navigation item.

        Returns a Rich ``Text`` so the literal ``[key]`` is never parsed as
        console markup (``[s]`` would otherwise toggle strikethrough). The
        rendered plain text stays ``[key] label`` for muscle memory and tests.
        """
        text = Text()
        text.append(f"[{self.key}]", style="bold")
        text.append(f" {self.label}")
        return text

    def set_active(self, active: bool) -> None:
        """Toggle the active-view cursor highlight (driven by CSS)."""
        self.active = active
        self.set_class(active, "-active")


class NavSeparator(Static):
    """A hairline divider in the navigation panel."""

    def render(self) -> Text:
        """Render a thin box-drawing hairline instead of an ASCII rule."""
        return Text(theme.ICON_LINE * 20, style=theme.MUTED)


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
        yield StatusBadge("SQL Audit", id="status-sql")
        yield StatusBadge("Web Audit", id="status-web")
        yield NavSeparator()

        yield Static("SCAN", classes="nav-group")
        yield NavItem("s", "Quick scan", id="nav-quick")
        yield NavItem("S", "Full scan", id="nav-full")
        yield NavItem("r", "Re-run all", id="nav-rerun")

        yield Static("VIEW", classes="nav-group")
        yield NavItem("o", "Overview", view="overview", id="nav-overview")
        yield NavItem("d", "Devices", view="devices", id="nav-devices")
        yield NavItem("f", "Findings", view="findings", id="nav-findings")
        yield NavItem("l", "Live log", view="live-log", id="nav-live-log")

        # Add telemetry status at the bottom
        yield Vertical(id="nav-bottom-spacer")
        yield TelemetryStatus(id="telemetry-status")

    def on_mount(self) -> None:
        """Update status on mount."""
        self.update_status()
        self.set_active_view("overview")

    def set_active_view(self, view: str) -> None:
        """Highlight the nav item for the active dashboard view."""
        for item in self.query(NavItem):
            if item.view is not None:
                item.set_active(item.view == view)

    def update_status(self) -> None:
        """Update all status badges."""
        status = get_scan_status()

        port_badge = self.query_one("#status-port", StatusBadge)
        pwd_badge = self.query_one("#status-pwd", StatusBadge)
        cve_badge = self.query_one("#status-cve", StatusBadge)
        sql_badge = self.query_one("#status-sql", StatusBadge)
        web_badge = self.query_one("#status-web", StatusBadge)

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

        if status["sql_scan"]:
            v = status["sql_vulns"]
            detail = "vulnerable" if v > 0 else "ok"
            sql_badge.set_status(True, detail)
        else:
            sql_badge.set_status(False)

        if status["web_scan"]:
            v = status["web_vulns"]
            detail = "vulnerable" if v > 0 else "ok"
            web_badge.set_status(True, detail)
        else:
            web_badge.set_status(False)


class NavigationPanel(NavPanel):
    """Sidebar navigation and status panel."""

    pass
