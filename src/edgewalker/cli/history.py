"""Render scan history (recent changes + score trend) for the CLI.

Pure rendering on top of the SQLite store's query methods — given the event
and trend dicts, returns Rich renderables. Kept separate from the command so
it is unit-testable without a console.
"""

from __future__ import annotations

# Third Party
from rich.table import Table
from rich.text import Text

# First Party
from edgewalker import theme

_SPARK = "▁▂▃▄▅▆▇█"

# Map a change-event severity label to a theme colour.
_SEVERITY_COLOR = {
    "CRITICAL": "RISK_CRITICAL",
    "HIGH": "WARNING",
    "MEDIUM": "ACCENT",
    "LOW": "SUCCESS",
    "INFO": "MUTED",
}


def sparkline(values: list[float]) -> str:
    """Render values as a unicode block sparkline."""
    if not values:
        return ""
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    return "".join(_SPARK[int((v - lo) / span * (len(_SPARK) - 1))] for v in values)


def _severity_color(severity: str | None) -> str:
    """Resolve a theme colour for a severity label (falls back to muted)."""
    return getattr(theme, _SEVERITY_COLOR.get((severity or "").upper(), "MUTED"), theme.MUTED)


def _format_detail(event_type: str, detail: dict) -> str:
    """Human-readable one-liner for an event's detail payload."""
    if "port" in detail:
        return f"port {detail['port']}"
    if "cve" in detail:
        return str(detail["cve"])
    if "service" in detail:
        return str(detail["service"])
    if event_type == "grade_changed":
        return f"{detail.get('from')} → {detail.get('to')}"
    if "stable_key" in detail:
        return str(detail["stable_key"])
    return ""


def build_history_view(events: list[dict], trend: list[dict]) -> list:
    """Build Rich renderables for the history view (score trend + change table)."""
    renderables: list = []

    if trend:
        spark = sparkline([t["score"] for t in trend])
        latest = trend[-1]
        renderables.append(
            Text.from_markup(
                f"[{theme.ACCENT}]Score trend[/] {spark}  "
                f"latest [bold]{latest['score']:.0f}[/] (grade {latest['grade']})"
            )
        )

    if events:
        table = Table(title="Recent changes", box=theme.BOX_STYLE, title_style=theme.HEADER)
        table.add_column("When", style=theme.MUTED, no_wrap=True)
        table.add_column("Event")
        table.add_column("Severity")
        table.add_column("Device", style=theme.MUTED)
        table.add_column("Detail")
        for e in events:
            device = e.get("label") or e.get("stable_key") or "—"
            sev = e.get("severity") or ""
            table.add_row(
                str(e["created_at"])[:19].replace("T", " "),
                e["event_type"],
                Text(sev, style=_severity_color(sev)),
                device,
                _format_detail(e["event_type"], e.get("detail", {})),
            )
        renderables.append(table)

    if not events and not trend:
        renderables.append(
            Text("No history yet. Run a scan to start tracking changes.", style=theme.MUTED)
        )

    return renderables
