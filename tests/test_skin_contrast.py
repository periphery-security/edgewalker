"""WCAG contrast guard for the bundled skins' muted colour.

Muted carries secondary/metadata text, so it must stay readable on the
skin background. We require at least the 3:1 (AA large / UI) floor — the
periphery skin's old #555555 (2.55:1) regressed below this.
"""

# Standard Library
from pathlib import Path

# Third Party
import pytest
import yaml

# First Party
import edgewalker

_SKINS_DIR = Path(edgewalker.__file__).parent / "skins"
_MIN_RATIO = 3.0


def _relative_luminance(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    channels = (int(hex_color[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def linear(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(c) for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast_ratio(fg: str, bg: str) -> float:
    light, dark = sorted((_relative_luminance(fg), _relative_luminance(bg)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


@pytest.mark.parametrize("skin_path", sorted(_SKINS_DIR.glob("*.yaml")), ids=lambda p: p.stem)
def test_skin_muted_clears_contrast_floor(skin_path):
    theme = yaml.safe_load(skin_path.read_text()).get("theme", {})
    muted = theme.get("variables", {}).get("muted", "")
    background = theme.get("background", "")
    assert muted.startswith("#") and background.startswith("#")

    ratio = _contrast_ratio(muted, background)
    assert ratio >= _MIN_RATIO, f"{skin_path.stem}: muted {muted} on {background} is {ratio:.2f}:1"
