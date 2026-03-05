# Standard Library
import os

# First Party
from edgewalker.core.config import Settings, save_settings
from edgewalker.utils import save_results


def test_save_results_permissions(tmp_path, monkeypatch):
    # Mock settings.output_dir to use tmp_path
    monkeypatch.setenv("EW_OUTPUT_DIR", str(tmp_path / "scans"))

    data = {"test": "data"}
    filename = "test_perms.json"
    output_path = save_results(data, filename)

    # Check file permissions
    mode = os.stat(output_path).st_mode
    assert oct(mode & 0o777) == "0o600"

    # Check directory permissions
    dir_mode = os.stat(output_path.parent).st_mode
    assert oct(dir_mode & 0o777) == "0o700"


def test_save_settings_permissions(tmp_path, monkeypatch):
    # Mock get_config_dir to use tmp_path
    monkeypatch.setenv("EW_CONFIG_DIR", str(tmp_path))

    settings = Settings()
    config_file = settings.config_file

    save_settings(settings)

    # Check file permissions
    mode = os.stat(config_file).st_mode
    assert oct(mode & 0o777) == "0o600"

    # Check directory permissions
    dir_mode = os.stat(config_file.parent).st_mode
    assert oct(dir_mode & 0o777) == "0o700"
