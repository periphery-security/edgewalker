"""Renderables for the redesigned dashboard overview.

Turns an :class:`~edgewalker.core.findings.AssessmentSummary` into the
multi-panel overview shown in the redesign mockup: a grade gauge, a network
summary, prioritised findings, and a device table. Pure Rich renderables so
they are trivial to unit-test and drop into a Textual ``Static``.
"""

from __future__ import annotations

# Standard Library
from typing import Optional

# Third Party
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# First Party
from edgewalker import theme
from edgewalker.core.findings import AssessmentSummary, Finding

#: Letter-grade -> style.
_GRADE_STYLE: dict[str, str] = {
    "A+": theme.SUCCESS,
    "A": theme.SUCCESS,
    "B": theme.ACCENT,
    "C": theme.WARNING,
    "D": theme.WARNING,
    "F": theme.DANGER,
}

#: Severity -> (chip style, sort already handled upstream).
_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": theme.RISK_CRITICAL,
    "HIGH": theme.RISK_HIGH,
    "MEDIUM": theme.RISK_MEDIUM,
    "LOW": theme.RISK_LOW,
}


def grade_style(grade: str) -> str:
    """Return the Rich style for a letter grade."""
    return _GRADE_STYLE.get(grade.upper(), theme.WARNING)


def severity_style(severity: str) -> str:
    """Return the Rich style for a finding severity."""
    return _SEVERITY_STYLE.get(severity.upper(), theme.MUTED)


def _score_bar(score: int, width: int = 22) -> Text:
    """Render a 0-100 score as a block bar, coloured by the matching grade."""
    score = max(0, min(100, score))
    filled = round(score / 100 * width)
    style = severity_style(_score_to_severity(score))
    bar = Text()
    bar.append("█" * filled, style=style)
    bar.append("░" * (width - filled), style=theme.MUTED)
    return bar


def _score_to_severity(score: int) -> str:
    """Map a 0-100 risk score to a severity bucket (for bar colour)."""
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_grade_panel(summary: AssessmentSummary) -> Panel:
    """The hero grade gauge: letter + score bar + one-line reason."""
    body = Table.grid(padding=(0, 1))
    body.add_column(justify="center")
    body.add_column(ratio=1)

    letter = Text(f" {summary.grade} ", style=f"bold {grade_style(summary.grade)}")

    right = Table.grid()
    right.add_row(_score_bar(summary.score))
    score_line = Text()
    score_line.append("score  ", style=theme.MUTED)
    score_line.append(f"{summary.score} / 100", style=theme.TEXT)
    right.add_row(score_line)
    right.add_row(Text(summary.grade_reason, style=grade_style(summary.grade)))

    body.add_row(letter, right)
    return Panel(
        body,
        title=f"[{theme.HEADER}]SECURITY GRADE[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )


def build_network_panel(summary: AssessmentSummary) -> Panel:
    """Network summary card: target, devices, open ports, gateway."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=theme.MUTED)
    grid.add_column(style=theme.TEXT, justify="right")
    grid.add_row("Target", summary.target or "—")
    grid.add_row("Devices found", str(summary.device_count))
    grid.add_row("Open ports", str(summary.open_ports))
    grid.add_row("Gateway", summary.gateway_ip or "—")
    return Panel(
        grid,
        title=f"[{theme.HEADER}]NETWORK[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )


def _finding_line(finding: Finding) -> Text:
    """One findings row: a severity chip + title + dim detail."""
    line = Text()
    line.append(f" {finding.severity:^8} ", style=f"bold {severity_style(finding.severity)}")
    line.append("  ")
    line.append(finding.title, style=theme.TEXT)
    if finding.host:
        line.append(f"  · {finding.host}", style=theme.MUTED)
    if finding.detail:
        line.append(f"  ({finding.detail})", style=theme.MUTED)
    return line


def build_findings_panel(summary: AssessmentSummary, limit: int = 6) -> Panel:
    """Top findings, most severe first."""
    if not summary.findings:
        body: RenderableType = Text(
            "No findings — nothing actionable detected.", style=theme.SUCCESS
        )
    else:
        lines = Table.grid()
        for finding in summary.findings[:limit]:
            lines.add_row(_finding_line(finding))
        extra = len(summary.findings) - limit
        if extra > 0:
            lines.add_row(Text(f"  … and {extra} more", style=theme.MUTED))
        body = lines
    return Panel(
        body,
        title=f"[{theme.HEADER}]TOP FINDINGS[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )


def _finding_matches(finding: Finding, query: str) -> bool:
    """Case-insensitive substring match across a finding's fields."""
    haystack = f"{finding.severity} {finding.title} {finding.host} {finding.detail}".lower()
    return query in haystack


def build_findings_view(summary: Optional[AssessmentSummary], query: str = "") -> RenderableType:
    """The dedicated findings view: every finding, most severe first.

    When ``query`` is set, only findings matching it (across severity, title,
    host, and detail) are shown.
    """
    query = query.strip().lower()
    if summary is None:
        body: RenderableType = Text("No assessment yet — press s to run a scan.", style=theme.MUTED)
    elif not summary.findings:
        body = Text("No findings — nothing actionable detected.", style=theme.SUCCESS)
    else:
        findings = [f for f in summary.findings if not query or _finding_matches(f, query)]
        if not findings:
            body = Text(f"No findings match “{query}”.", style=theme.MUTED)
        else:
            lines = Table.grid()
            for finding in findings:
                lines.add_row(_finding_line(finding))
            body = lines
    title = "FINDINGS" if not query else f"FINDINGS · filter “{query}”"
    return Panel(
        body,
        title=f"[{theme.HEADER}]{title}[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )


def build_device_table(summary: AssessmentSummary) -> Panel:
    """Device table sorted by risk score, with coloured risk levels."""
    table = Table(box=None, expand=True, pad_edge=False)
    table.add_column("HOST", style=theme.TEXT)
    table.add_column("VENDOR", style=theme.MUTED)
    table.add_column("PORTS", justify="right", style=theme.TEXT)
    table.add_column("SERVICE", style=theme.MUTED)
    table.add_column("RISK", justify="right")

    for device in summary.devices:
        sev = _score_to_severity(device.score) if device.score else "LOW"
        risk = Text(f"{device.risk_level} · {device.score}", style=severity_style(sev))
        table.add_row(
            device.ip,
            device.vendor,
            str(device.port_count),
            device.top_service,
            risk,
        )

    return Panel(
        table,
        title=f"[{theme.HEADER}]DEVICES[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )


def build_overview(summary: Optional[AssessmentSummary]) -> RenderableType:
    """Compose the full overview, or an empty-state call to action."""
    if summary is None:
        return build_overview_empty()

    top = Table.grid(expand=True, padding=(0, 1))
    top.add_column(ratio=1)
    top.add_column(ratio=1)
    top.add_row(build_grade_panel(summary), build_network_panel(summary))

    return Group(
        top,
        build_findings_panel(summary),
        build_device_table(summary),
    )


def build_overview_empty() -> RenderableType:
    """Call-to-action shown before any scan has run."""
    body = Text()
    body.append("No assessment yet.\n\n", style=f"bold {theme.TEXT}")
    body.append("Press ", style=theme.MUTED)
    body.append("s", style=f"bold {theme.ACCENT}")
    body.append(" to run a quick scan, or ", style=theme.MUTED)
    body.append("S", style=f"bold {theme.ACCENT}")
    body.append(" for a full scan.", style=theme.MUTED)
    return Panel(
        body,
        title=f"[{theme.HEADER}]OVERVIEW[/]",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
    )
