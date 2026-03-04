"""EdgeWalker Visual Helpers.

Rich-based rendering helpers for CLI and TUI.
"""

from __future__ import annotations

# Third Party
from rich.color import Color
from rich.console import Console
from rich.style import Style
from rich.text import Text as RichText

# First Party
from edgewalker.core.constants import GRADE_ART


def get_ui_width() -> int:
    """Return the current terminal width."""
    return Console().width


def get_inner_width() -> int:
    """Return the inner width for content (width - padding)."""
    return get_ui_width() - 6


def gradient_text(text: str, start_hex: str, end_hex: str) -> RichText:
    """Return a Rich Text object with a left-to-right color gradient."""

    def _hex_to_rgb(h: str) -> tuple[int, int, int]:
        """Convert a hex color string to an RGB tuple."""
        h = h.lstrip("#")
        return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))

    r1, g1, b1 = _hex_to_rgb(start_hex)
    r2, g2, b2 = _hex_to_rgb(end_hex)

    result = RichText()
    length = len(text)
    if length == 0:
        return result

    for i, ch in enumerate(text):
        t = i / max(length - 1, 1)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        result.append(ch, style=Style(color=Color.from_rgb(r, g, b), bold=True))
    return result


def health_bar(
    score: int,
    success_color: str,
    warning_color: str,
    danger_color: str,
    muted_color: str,
    bar_full_icon: str,
    bar_light_icon: str,
    width: int = None,
) -> RichText:
    """Return a Rich Text health bar with gradient coloring."""
    if width is None:
        width = get_inner_width()

    filled = int(width * score / 100)
    empty = width - filled

    bar = RichText()

    # Color transitions: green (high) -> yellow (mid) -> red (low)
    for _ in range(filled):
        if score >= 70:
            color = success_color
        elif score >= 40:
            color = warning_color
        else:
            color = danger_color
        bar.append(bar_full_icon, style=Style(color=Color.parse(color)))

    bar.append(bar_light_icon * empty, style=Style(color=Color.parse(muted_color)))
    return bar


def risk_badge(
    level: str,
    danger_color: str,
    warning_color: str,
    success_color: str,
    skull_icon: str,
    warn_icon: str,
    check_icon: str,
) -> str:
    """Return a Rich markup risk badge string."""
    badges = {
        "CRITICAL": f"[bold {danger_color}]{skull_icon} CRITICAL[/bold {danger_color}]",
        "HIGH": f"[{danger_color}]{warn_icon} HIGH[/{danger_color}]",
        "MEDIUM": f"[{warning_color}]{warn_icon} MEDIUM[/{warning_color}]",
        "LOW": f"[{success_color}]{check_icon} LOW[/{success_color}]",
        "NONE": f"[dim]{check_icon} NONE[/dim]",
    }
    return badges.get(level, f"[dim]{level}[/dim]")


def grade_art(grade: str, color: str) -> RichText:
    """Return a Rich Text block with a large ASCII art grade letter."""
    lines = GRADE_ART.get(grade, GRADE_ART["F"])
    result = RichText()
    for line in lines:
        result.append(f"  {line}\n", style=f"bold {color}")
    return result


def severity_badge(severity: str, danger_color: str, warning_color: str, success_color: str) -> str:
    """Return a Rich markup severity badge for CVE display."""
    badges = {
        "CRITICAL": f"[bold {danger_color}]CRIT[/bold {danger_color}]",
        "HIGH": f"[{danger_color}]HIGH[/{danger_color}]",
        "MEDIUM": f"[{warning_color}]MED[/{warning_color}]",
        "LOW": f"[{success_color}]LOW[/{success_color}]",
    }
    return badges.get(severity, f"[dim]{severity}[/dim]")
