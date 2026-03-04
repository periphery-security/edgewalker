# Third Party
from rich.text import Text as RichText

# First Party
from edgewalker.core import visuals


def test_visuals_widths():
    assert visuals.get_ui_width() > 0
    assert visuals.get_inner_width() < visuals.get_ui_width()


def test_gradient_text():
    res = visuals.gradient_text("Test", "#FF0000", "#0000FF")
    assert isinstance(res, RichText)
    assert len(res) == 4

    assert len(visuals.gradient_text("", "#FF0000", "#0000FF")) == 0


def test_health_bar():
    # Use hex colors to avoid parsing issues
    res = visuals.health_bar(50, "#00FF00", "#FFFF00", "#FF0000", "#808080", "█", "░", width=10)
    assert len(res) == 10
    assert "█" in res.plain
    assert "░" in res.plain


def test_risk_badge():
    assert "CRITICAL" in visuals.risk_badge("CRITICAL", "red", "yellow", "green", "💀", "⚠", "✔")
    assert "UNKNOWN" in visuals.risk_badge("UNKNOWN", "red", "yellow", "green", "💀", "⚠", "✔")


def test_grade_art():
    res = visuals.grade_art("A", "green")
    assert isinstance(res, RichText)
    assert len(res) > 0


def test_severity_badge():
    assert "CRIT" in visuals.severity_badge("CRITICAL", "red", "yellow", "green")
    assert "LOW" in visuals.severity_badge("LOW", "red", "yellow", "green")
