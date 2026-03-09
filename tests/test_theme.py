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


def test_colorblind_skin_exists_and_has_required_keys():
    """colorblind.yaml skin exists and defines all required color roles."""
    # Standard Library
    from pathlib import Path

    skin_path = Path(__file__).parent.parent / "src/edgewalker/skins/colorblind.yaml"
    assert skin_path.exists(), "colorblind.yaml skin file missing"

    # Third Party
    import yaml

    data = yaml.safe_load(skin_path.read_text())
    theme_section = data.get("theme", {})
    for key in ("primary", "accent", "success", "warning", "error", "foreground"):
        assert key in theme_section, f"colorblind skin missing key: {key}"


def test_colorblind_skin_loads_via_theme_manager():
    """ThemeManager can load the colorblind skin without errors."""
    # First Party
    from edgewalker.core.theme_manager import ThemeManager

    tm = ThemeManager()
    data = tm.load_theme("colorblind")
    assert data.get("theme", {}).get("accent") is not None


def test_colorblind_flag_reloads_theme():
    """apply_colorblind_theme switches the active theme."""
    # First Party
    from edgewalker import theme as t
    from edgewalker.cli.cli import apply_colorblind_theme

    original_accent = t.ACCENT
    # Test without persistence first
    apply_colorblind_theme(persist=False)
    # accent should now be the colorblind skin's value, not the periphery cyan
    assert t.ACCENT != "#00FFFF"

    # restore
    # First Party
    from edgewalker.core.config import settings

    settings.theme = "periphery"
    t.load_active_theme()
