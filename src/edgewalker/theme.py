"""EdgeWalker TUI and CLI Theme.

Defines colors, icons, and styles used throughout the application.
"""

from __future__ import annotations

# Third Party
from rich import box
from rich.text import Text as RichText

# First Party
from edgewalker.core import constants, visuals
from edgewalker.core.config import settings
from edgewalker.core.theme_manager import theme_manager

# -- Theme Loading ---------------------------------------------------------


def load_active_theme() -> None:
    """Load the active theme from settings and populate global constants."""
    theme_data = theme_manager.load_theme(settings.theme)

    theme_colors = theme_data.get("theme", {})
    variables = theme_colors.get("variables", {})
    icons = theme_data.get("icons", {})

    global PRIMARY, ACCENT, SECONDARY, LAVENDER, SUCCESS, WARNING, DANGER, MUTED, TEXT, HIGHLIGHT
    global \
        ICON_SCAN, \
        ICON_CHECK, \
        ICON_FAIL, \
        ICON_BULLET, \
        ICON_ARROW, \
        ICON_WARN, \
        ICON_SKULL, \
        ICON_VULN
    global ICON_CIRCLE, ICON_CIRCLE_FILLED, ICON_STEP, ICON_PLUS, ICON_INFO, ICON_ALERT
    global BAR_FULL, BAR_LIGHT
    global BOX_STYLE
    global \
        HEADER, \
        SUBHEADER, \
        RISK_CRITICAL, \
        RISK_HIGH, \
        RISK_MEDIUM, \
        RISK_LOW, \
        RISK_NONE, \
        SCAN_ACTIVE, \
        MUTED_STYLE

    # -- Color Palette -----------------------------------------------------
    PRIMARY = theme_colors.get("primary", "#5A00FF")
    ACCENT = theme_colors.get("accent", "#00FFFF")
    SECONDARY = theme_colors.get("secondary", "#8F88FF")
    LAVENDER = theme_colors.get("lavender", "#C4B9FF")
    SUCCESS = theme_colors.get("success", "#00ff41")
    WARNING = theme_colors.get("warning", "#ffb800")
    DANGER = theme_colors.get("error", "#DC0000")
    TEXT = theme_colors.get("foreground", "#c0c0c0")
    MUTED = variables.get("muted", f"{TEXT} 50%")
    HIGHLIGHT = theme_colors.get("highlight", "#FFFEB2")

    # -- Icons -------------------------------------------------------------
    # Semantic icons (customizable via theme)
    ICON_SCAN = icons.get("scan", "⌕")
    ICON_CHECK = icons.get("check", "✔")
    ICON_FAIL = icons.get("fail", "✘")
    ICON_BULLET = icons.get("bullet", "•")
    ICON_ARROW = icons.get("arrow", "→")
    ICON_WARN = icons.get("warn", "⚠")
    ICON_SKULL = icons.get("skull", "☠")
    ICON_VULN = icons.get("vulnerable", "✘")

    # TUI specific icons
    ICON_CIRCLE = icons.get("circle", "○")
    ICON_CIRCLE_FILLED = icons.get("circle_filled", "●")
    ICON_STEP = icons.get("step", "↳")
    ICON_PLUS = icons.get("plus", "[+]")
    ICON_INFO = icons.get("info", "[*]")
    ICON_ALERT = icons.get("alert", "[!]")

    # Health-bar blocks
    BAR_FULL = icons.get("bar_full", "█")
    BAR_LIGHT = icons.get("bar_light", "░")

    # -- Layout Constants --------------------------------------------------
    BOX_STYLE = box.ROUNDED

    # -- Style Presets -----------------------------------------------------
    HEADER = f"bold {ACCENT}"
    SUBHEADER = "bold bright_white"
    RISK_CRITICAL = f"bold {DANGER}"
    RISK_HIGH = DANGER
    RISK_MEDIUM = WARNING
    RISK_LOW = SUCCESS
    RISK_NONE = "dim"
    SCAN_ACTIVE = f"bold {ACCENT}"
    MUTED_STYLE = MUTED


# Initial load
load_active_theme()

# -- Re-export from Core ---------------------------------------------------


def get_ui_width() -> int:
    """Return the current terminal width."""
    return visuals.get_ui_width()


def get_inner_width() -> int:
    """Return the inner width for content (width - padding)."""
    return visuals.get_inner_width()


# Structural Constants (Hardcoded for consistency)
ICON_DOT = constants.ICON_DOT
ICON_UP = constants.ICON_UP
ICON_DOWN = constants.ICON_DOWN
ICON_LINE = constants.ICON_LINE
ICON_LINE_BOLD = constants.ICON_LINE_BOLD

# ASCII Logo
LOGO = constants.LOGO
TAGLINE = constants.TAGLINE

# -- Helper: gradient text --------------------------------------------------


def gradient_text(text: str, start_hex: str = None, end_hex: str = None) -> RichText:
    """Return a Rich Text object with a left-to-right color gradient."""
    return visuals.gradient_text(text, start_hex or PRIMARY, end_hex or ACCENT)


def health_bar(score: int, width: int = None) -> RichText:
    """Return a Rich Text health bar with gradient coloring."""
    return visuals.health_bar(score, SUCCESS, WARNING, DANGER, MUTED, BAR_FULL, BAR_LIGHT, width)


def risk_badge(level: str) -> str:
    """Return a Rich markup risk badge string."""
    return visuals.risk_badge(level, DANGER, WARNING, SUCCESS, ICON_SKULL, ICON_WARN, ICON_CHECK)


def grade_art(grade: str, color: str) -> RichText:
    """Return a Rich Text block with a large ASCII art grade letter."""
    return visuals.grade_art(grade, color)


def severity_badge(severity: str) -> str:
    """Return a Rich markup severity badge for CVE display."""
    return visuals.severity_badge(severity, DANGER, WARNING, SUCCESS)
