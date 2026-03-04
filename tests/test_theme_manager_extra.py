# Standard Library

# Third Party

# First Party
from edgewalker.core.theme_manager import ThemeManager


def test_theme_manager_discovery(tmp_path):
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "theme1.yaml").write_text("metadata: {name: Theme 1}")

    user = tmp_path / "user"
    user.mkdir()
    (user / "theme2.yaml").write_text("metadata: {name: Theme 2}")

    tm = ThemeManager()
    tm.bundled_dir = bundled
    tm.user_dir = user

    themes = tm.discover_themes()
    assert "theme1" in themes
    assert "theme2" in themes


def test_theme_manager_load(tmp_path):
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "periphery.yaml").write_text("theme: {primary: blue}")
    (bundled / "other.yaml").write_text("theme: {primary: red}")

    tm = ThemeManager()
    tm.bundled_dir = bundled
    tm.discover_themes()

    data = tm.load_theme("other")
    assert data["theme"]["primary"] == "red"

    data_default = tm.load_theme("periphery")
    assert data_default["theme"]["primary"] == "blue"


def test_theme_manager_metadata(tmp_path):
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "test.yaml").write_text("metadata: {name: Test, author: Me}")

    tm = ThemeManager()
    tm.bundled_dir = bundled
    tm.discover_themes()

    meta = tm.get_theme_metadata("test")
    assert meta["name"] == "Test"
    assert meta["author"] == "Me"


def test_load_textual_theme(tmp_path):
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "periphery.yaml").write_text("theme: {primary: '#0000FF'}")

    tm = ThemeManager()
    tm.bundled_dir = bundled

    theme = tm.load_textual_theme("periphery")
    assert theme is not None
    assert theme.name == "periphery"
