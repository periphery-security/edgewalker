# Standard Library
import os
from unittest.mock import patch

# Third Party
import pytest

# First Party
from edgewalker.core import config


def test_init_config(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        config.init_config()
        assert (tmp_path / "config.yaml").exists()


def test_init_config_survives_unchmodable_dir(tmp_path):
    """A root-owned dir (chmod fails) must warn, not crash startup."""
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        with patch("edgewalker.core.config.os.chmod", side_effect=PermissionError("not permitted")):
            # Should not raise despite chmod failing on every directory.
            config.init_config()


def test_update_setting(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        # Test int conversion
        config.update_setting("api_timeout", "20")
        assert config.settings.api_timeout == 20

        # Test bool conversion
        config.update_setting("telemetry_enabled", "true")
        assert config.settings.telemetry_enabled is True

        # Test float conversion
        config.update_setting("nmap_timeout", 1000.5)
        assert config.settings.nmap_timeout == 1000

        # Test invalid setting
        with pytest.raises(AttributeError):
            config.update_setting("invalid_key", "val")
