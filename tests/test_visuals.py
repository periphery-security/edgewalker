# Standard Library
from unittest.mock import patch

# Third Party
from rich.text import Text as RichText

# First Party
from edgewalker.core.visuals import (
    get_inner_width,
    get_ui_width,
    grade_art,
    gradient_text,
    health_bar,
    risk_badge,
    severity_badge,
)


def test_get_ui_width():
    with patch("edgewalker.core.visuals.Console") as mock_console:
        mock_console.return_value.width = 120
        assert get_ui_width() == 120

        mock_console.return_value.width = 80
        assert get_ui_width() == 80


def test_get_inner_width():
    with patch("edgewalker.core.visuals.get_ui_width", return_value=100):
        assert get_inner_width() == 94


def test_gradient_text():
    res = gradient_text("Hello", "#FF0000", "#0000FF")
    assert isinstance(res, RichText)
    assert len(res) == 5

    res_empty = gradient_text("", "#FF0000", "#0000FF")
    assert len(res_empty) == 0


def test_health_bar():
    res = health_bar(
        score=80,
        success_color="#00FF00",
        warning_color="#FFFF00",
        danger_color="#FF0000",
        muted_color="#808080",
        bar_full_icon="█",
        bar_light_icon="░",
        width=10,
    )
    assert isinstance(res, RichText)
    assert len(res) == 10

    # Test different scores for color coverage
    health_bar(50, "#00FF00", "#FFFF00", "#FF0000", "#808080", "█", "░", 10)
    health_bar(20, "#00FF00", "#FFFF00", "#FF0000", "#808080", "█", "░", 10)

    # Test without width
    with patch("edgewalker.core.visuals.get_inner_width", return_value=10):
        health_bar(80, "#00FF00", "#FFFF00", "#FF0000", "#808080", "█", "░")


def test_risk_badge():
    assert "CRITICAL" in risk_badge("CRITICAL", "red", "yellow", "green", "💀", "⚠", "✓")
    assert "HIGH" in risk_badge("HIGH", "red", "yellow", "green", "💀", "⚠", "✓")
    assert "MEDIUM" in risk_badge("MEDIUM", "red", "yellow", "green", "💀", "⚠", "✓")
    assert "LOW" in risk_badge("LOW", "red", "yellow", "green", "💀", "⚠", "✓")
    assert "NONE" in risk_badge("NONE", "red", "yellow", "green", "💀", "⚠", "✓")
    assert "UNKNOWN" in risk_badge("UNKNOWN", "red", "yellow", "green", "💀", "⚠", "✓")


def test_grade_art():
    res = grade_art("A", "green")
    assert isinstance(res, RichText)
    assert len(res) > 0

    res_f = grade_art("F", "red")
    assert len(res_f) > 0


def test_severity_badge():
    assert "CRIT" in severity_badge("CRITICAL", "red", "yellow", "green")
    assert "HIGH" in severity_badge("HIGH", "red", "yellow", "green")
    assert "MED" in severity_badge("MEDIUM", "red", "yellow", "green")
    assert "LOW" in severity_badge("LOW", "red", "yellow", "green")
    assert "UNKNOWN" in severity_badge("UNKNOWN", "red", "yellow", "green")
