# Standard Library
from unittest.mock import patch

# Third Party
import pytest
import yaml

# First Party
from edgewalker.core.theme_manager import ThemeManager


@pytest.fixture
def theme_manager(tmp_path):
    with patch("edgewalker.core.theme_manager.user_config_dir", return_value=str(tmp_path)):
        tm = ThemeManager()
        tm.bundled_dir = tmp_path / "bundled"
        tm.user_dir = tmp_path / "user"
        tm.bundled_dir.mkdir()
        tm.user_dir.mkdir()
        return tm


def test_discover_themes(theme_manager):
    (theme_manager.bundled_dir / "test1.yaml").write_text("name: test1")
    (theme_manager.user_dir / "test2.yaml").write_text("name: test2")
    (theme_manager.user_dir / "test1.yaml").write_text("name: test1-user")

    themes = theme_manager.discover_themes()
    assert "test1" in themes
    assert "test2" in themes
    assert themes["test1"] == theme_manager.user_dir / "test1.yaml"


def test_get_theme_metadata(theme_manager):
    path = theme_manager.bundled_dir / "test.yaml"
    path.write_text(yaml.dump({"metadata": {"name": "Test Theme", "author": "Alice"}}))
    theme_manager._themes["test"] = path

    meta = theme_manager.get_theme_metadata("test")
    assert meta["name"] == "Test Theme"
    assert meta["author"] == "Alice"

    # Cached
    assert theme_manager.get_theme_metadata("test") == meta


def test_get_theme_metadata_not_found(theme_manager):
    meta = theme_manager.get_theme_metadata("nonexistent")
    assert meta["name"] == "nonexistent"
    assert meta["author"] == "Unknown"


def test_get_theme_metadata_error(theme_manager):
    path = theme_manager.bundled_dir / "error.yaml"
    path.write_text("invalid: yaml: :")
    theme_manager._themes["error"] = path
    meta = theme_manager.get_theme_metadata("error")
    assert meta["name"] == "error"


def test_list_themes(theme_manager):
    (theme_manager.bundled_dir / "test.yaml").write_text(yaml.dump({"metadata": {"name": "Test"}}))
    themes = theme_manager.list_themes()
    assert len(themes) == 1
    assert themes[0]["slug"] == "test"


def test_load_theme_periphery(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_data = {"theme": {"primary": "blue"}}
    periphery_path.write_text(yaml.dump(periphery_data))

    data = theme_manager.load_theme("periphery")
    assert data["theme"]["primary"] == "blue"


def test_load_theme_merge(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_data = {"theme": {"primary": "blue", "secondary": "green"}}
    periphery_path.write_text(yaml.dump(periphery_data))

    user_path = theme_manager.user_dir / "custom.yaml"
    user_data = {"theme": {"primary": "red"}}
    user_path.write_text(yaml.dump(user_data))
    theme_manager._themes["custom"] = user_path

    data = theme_manager.load_theme("custom")
    assert data["theme"]["primary"] == "red"
    assert data["theme"]["secondary"] == "green"


def test_load_theme_periphery_error(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_path.write_text("invalid: yaml: :")
    data = theme_manager.load_theme("periphery")
    assert data == {}


def test_load_theme_empty_file(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_path.write_text("")
    data = theme_manager.load_theme("periphery")
    assert data == {}


def test_load_theme_merge_missing_section(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_path.write_text(yaml.dump({}))

    user_path = theme_manager.user_dir / "custom.yaml"
    user_data = {"theme": {"primary": "red"}}
    user_path.write_text(yaml.dump(user_data))
    theme_manager._themes["custom"] = user_path

    data = theme_manager.load_theme("custom")
    assert data["theme"]["primary"] == "red"


def test_load_textual_theme(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_data = {"theme": {"primary": "blue", "background": "black"}}
    periphery_path.write_text(yaml.dump(periphery_data))

    with patch("edgewalker.core.theme_manager.Theme") as mock_theme:
        theme_manager.load_textual_theme("periphery")
        mock_theme.assert_called_once()
        args, kwargs = mock_theme.call_args
        assert kwargs["primary"] == "blue"
        assert kwargs["background"] == "black"


def test_load_theme_error(theme_manager):
    path = theme_manager.bundled_dir / "error.yaml"
    path.write_text("name: error")
    theme_manager.discover_themes()

    with patch("builtins.open", side_effect=Exception("Read error")):
        data = theme_manager.load_theme("error")
        assert data == {}


def test_load_textual_theme_error(theme_manager):
    periphery_path = theme_manager.bundled_dir / "periphery.yaml"
    periphery_path.write_text(yaml.dump({"theme": {"primary": "blue"}}))

    with patch("edgewalker.core.theme_manager.Theme", side_effect=Exception("Invalid theme")):
        res = theme_manager.load_textual_theme("periphery")
        assert res is None
