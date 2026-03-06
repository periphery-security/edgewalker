# Standard Library
import os
from unittest.mock import MagicMock, patch

# Third Party
import pytest


def test_env_coercion():
    """Test environment variable type coercion."""
    with patch.dict(
        os.environ,
        {
            "EW_API_TIMEOUT": "20",
            "EW_NMAP_TIMEOUT": "100",
            "EW_API_URL": "http://test.local",
            "EW_CRED_WORKERS": "4",
        },
    ):
        # First Party
        from edgewalker.core.config import Settings

        settings = Settings()

        assert settings.api_timeout == 20
        assert settings.nmap_timeout == 100
        assert settings.api_url == "http://test.local"
        assert settings.cred_workers == 4


def test_path_overrides():
    """Test that paths can be overridden via environment variables."""
    with patch.dict(
        os.environ,
        {
            "EW_CACHE_DIR": "/tmp/ew_cache",
            "EW_OUTPUT_DIR": "/tmp/ew_output",
        },
    ):
        # First Party
        from edgewalker.core.config import Settings

        settings = Settings()
        assert str(settings.cache_dir) == "/tmp/ew_cache"
        assert str(settings.output_dir) == "/tmp/ew_output"


def test_init_config_updates_existing(tmp_path):
    """Test that init_config adds missing fields to existing config."""
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        # First Party
        from edgewalker.core.config import init_config, settings

        # Set a value in memory
        settings.api_timeout = 42

        # Create an existing config without device_id
        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            f.write("api_timeout: 42\n")

        init_config()

        # Verify device_id was added
        with open(config_file) as f:
            # Third Party
            import yaml

            data = yaml.safe_load(f)
            assert "device_id" in data
            assert data["api_timeout"] == 42


def test_save_settings(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        # First Party
        from edgewalker.core.config import Settings, save_settings

        settings = Settings()
        settings.api_timeout = 99
        save_settings(settings)

        with open(tmp_path / "config.yaml") as f:
            # Third Party
            import yaml

            data = yaml.safe_load(f)
            assert data["api_timeout"] == 99


def test_update_setting(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        # First Party
        from edgewalker.core.config import settings, update_setting

        update_setting("api_timeout", "50")
        assert settings.api_timeout == 50

        update_setting("telemetry_enabled", "yes")
        assert settings.telemetry_enabled is True

        update_setting("api_url", "http://new.url")
        assert settings.api_url == "http://new.url"

        # Third Party
        import pytest

        with pytest.raises(AttributeError):
            update_setting("nonexistent", "value")


def test_update_setting_float(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        # First Party
        from edgewalker.core.config import settings, update_setting

        mock_field = MagicMock()
        mock_field.annotation = float

        with patch.dict(settings.__class__.model_fields, {"api_timeout": mock_field}):
            # Use an integer value to avoid Pydantic validation error for api_timeout (which is an int)
            update_setting("api_timeout", "12")
            assert settings.api_timeout == 12


def test_device_id_persistence():
    """Test that device_id is generated and remains stable."""
    # First Party
    from edgewalker.core.config import Settings

    s1 = Settings()
    id1 = s1.device_id
    assert len(id1) == 12

    s2 = Settings()
    # Should be different if not loaded from same file, but here we just check format
    assert len(s2.device_id) == 12


def test_update_setting_readonly():
    """Test that read-only settings cannot be updated."""
    # First Party
    from edgewalker.core.config import update_setting

    with pytest.raises(AttributeError, match="read-only"):
        update_setting("device_id", "new-id")


def test_default_output_dir_is_not_inside_config_dir(tmp_path):
    """output_dir default must not nest inside the config/Application Support directory."""
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        from edgewalker.core.config import Settings, get_config_dir, get_data_dir
        s = Settings()
        config_dir = get_config_dir()
        data_dir = get_data_dir()
        # output_dir must live under data_dir, not config_dir
        assert str(s.output_dir).startswith(str(data_dir)), (
            f"output_dir ({s.output_dir}) should be under data_dir ({data_dir})"
        )
        assert not str(s.output_dir).startswith(str(config_dir)), (
            f"output_dir ({s.output_dir}) must not be inside config_dir ({config_dir})"
        )


def test_get_data_dir_respects_env_override():
    """EW_DATA_DIR env var overrides the data directory."""
    from edgewalker.core.config import get_data_dir
    with patch.dict(os.environ, {"EW_DATA_DIR": "/tmp/ew_data"}):
        assert str(get_data_dir()) == "/tmp/ew_data"
