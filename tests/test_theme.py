# Third Party
from rich.text import Text

# First Party
from edgewalker import theme


def test_gradient_text():
    res = theme.gradient_text("Test")
    assert isinstance(res, Text)
    assert len(res) == 4

    res_empty = theme.gradient_text("")
    assert len(res_empty) == 0


def test_severity_badge():
    res = theme.severity_badge("CRITICAL")
    assert "CRIT" in str(res)

    res_unknown = theme.severity_badge("UNKNOWN")
    assert "UNKNOWN" in str(res_unknown)


def test_grade_art():
    res = theme.grade_art("A", "green")
    assert isinstance(res, Text)
    assert len(res) > 0


def test_icons():
    assert theme.ICON_PLUS == "[+]"
    assert theme.ICON_INFO == "[*]"
    assert theme.ICON_ALERT == "[!]"
