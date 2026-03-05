# Standard Library
import os
from pathlib import Path
from unittest.mock import patch

# Third Party
import pytest
import yaml
from loguru import logger

# First Party
from edgewalker.core.config import Settings, get_active_overrides, init_config, update_setting


@pytest.fixture
def caplog_loguru(caplog):
    """Fixture to capture loguru logs with caplog."""
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


def test_validate_urls_domain_warnings(caplog_loguru):
    """Test domain warnings in validate_urls."""
    # We need to bypass the PYTEST_CURRENT_TEST check to test warnings
    with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}):
        settings = Settings()

        # Test api_url warning
        settings.api_url = "https://malicious.com/api"
        assert "Non-standard EdgeWalker API URL detected" in caplog_loguru.text

        # Test nvd_api_url warning
        caplog_loguru.clear()
        settings.nvd_api_url = "https://malicious-nvd.com/api"
        assert "Non-standard NVD API URL detected" in caplog_loguru.text

        # Test mac_api_url warning
        caplog_loguru.clear()
        settings.mac_api_url = "https://malicious-mac.com/api"
        assert "Non-standard MAC Lookup API URL detected" in caplog_loguru.text


def test_handle_demo_mode_env_var():
    """Test handle_demo_mode with EW_DEMO_MODE=1."""
    with patch.dict(os.environ, {"EW_DEMO_MODE": "1"}):
        settings = Settings()
        assert settings.output_dir.name == "demo_scans"


def test_get_security_warnings_no_test_env():
    """Test get_security_warnings when not in test environment."""
    with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}):
        settings = Settings()
        # Use https to avoid validation error, but non-standard domain to trigger warning
        settings.api_url = "https://insecure.com"
        warnings = settings.get_security_warnings()
        assert any("Non-standard EdgeWalker API URL" in w for w in warnings)


def test_get_field_info_errors_and_warnings():
    """Test get_field_info for non-existent fields and security warnings."""
    settings = Settings()

    # Test AttributeError for non-existent field
    with pytest.raises(AttributeError, match="Setting 'non_existent' does not exist"):
        settings.get_field_info("non_existent")

    # Test security warning in field info
    with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}):
        settings.api_url = "https://malicious.com/api"
        info = settings.get_field_info("api_url")
        assert info["security_warning"] is not None
        assert "Non-standard EdgeWalker API URL" in info["security_warning"]


def test_get_active_overrides_with_env_and_file(tmp_path):
    """Test get_active_overrides with both .env file and environment variables."""
    env_file = tmp_path / ".env"
    env_file.write_text("EW_API_URL=https://env-file.com\n# Comment\nINVALID_LINE\nEW_THEME=dark")

    with (
        patch(
            "edgewalker.core.config.Path",
            side_effect=lambda *args: Path(*args) if args[0] != ".env" else env_file,
        ),
        patch.dict(os.environ, {"EW_API_URL": "https://env-var.com", "PYTEST_CURRENT_TEST": ""}),
    ):
        overrides = get_active_overrides()
        assert overrides["EW_API_URL"] == "environment variable"
        assert overrides["EW_THEME"] == ".env file"


def test_init_config_with_overrides_and_warnings(caplog_loguru, tmp_path):
    """Test init_config behavior with overrides and security warnings."""
    with (
        patch("edgewalker.core.config.get_config_dir", return_value=tmp_path),
        patch(
            "edgewalker.core.config.get_active_overrides",
            return_value={"EW_THEME": "environment variable"},
        ),
        patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}),
    ):
        # Mock get_security_warnings to return something
        with patch.object(Settings, "get_security_warnings", return_value=["Test Warning"]):
            init_config()
            assert "Configuration overrides detected" in caplog_loguru.text
            assert "Test Warning" in caplog_loguru.text


def test_init_config_existing_config_update(tmp_path):
    """Test init_config updating an existing config file missing device_id."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    # Create config without device_id
    with open(config_file, "w") as f:
        f.write("theme: dracula\n")

    with patch("edgewalker.core.config.get_config_dir", return_value=config_dir):
        # settings.config_file uses get_config_dir() / "config.yaml"
        init_config()

        with open(config_file, "r") as f:
            data = yaml.safe_load(f)
            assert "device_id" in data


def test_validate_urls_http_localhost():
    """Test validate_urls allowing http for localhost."""
    settings = Settings()
    # Should not raise ValueError
    settings.api_url = "http://localhost:8080"
    assert settings.api_url == "http://localhost:8080"


def test_validate_urls_http_error():
    """Test validate_urls raising error for non-localhost http."""
    with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}):
        settings = Settings()
        with pytest.raises(ValueError, match="must use https for security"):
            settings.api_url = "http://malicious.com"


def test_get_security_warnings_all_insecure_urls():
    """Test get_security_warnings for all insecure URLs."""
    with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}):
        settings = Settings()
        # Bypass validator to set http
        with patch.dict(os.environ, {"PYTEST_CURRENT_TEST": "1"}):
            settings.api_url = "http://insecure-api.com"
            settings.nvd_api_url = "http://insecure-nvd.com"
            settings.mac_api_url = "http://insecure-mac.com"

        warnings = settings.get_security_warnings()
        assert any("Insecure (non-HTTPS) API URL" in w for w in warnings)
        assert any("Insecure (non-HTTPS) NVD API URL" in w for w in warnings)
        assert any("Insecure (non-HTTPS) MAC API URL" in w for w in warnings)


def test_update_setting_float_conversion(tmp_path):
    """Test float conversion in update_setting using a subclass."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    class TestSettings(Settings):
        float_field: float = 1.0

    test_settings = TestSettings()

    with (
        patch("edgewalker.core.config.get_config_dir", return_value=config_dir),
        patch("edgewalker.core.config.settings", test_settings),
    ):
        update_setting("float_field", "10.5")
        assert test_settings.float_field == 10.5


def test_get_active_overrides_env_file_error(tmp_path):
    """Test get_active_overrides handling .env file read error."""
    env_file = tmp_path / ".env"
    env_file.write_text("EW_THEME=dark")

    with (
        patch(
            "edgewalker.core.config.Path",
            side_effect=lambda *args: Path(*args) if args[0] != ".env" else env_file,
        ),
        patch("builtins.open", side_effect=OSError("Read error")),
        patch.dict(os.environ, {"PYTEST_CURRENT_TEST": ""}),
    ):
        overrides = get_active_overrides()
        assert overrides == {}  # Should fail silently and return empty dict


def test_init_config_existing_config_error(tmp_path):
    """Test init_config handling existing config read error."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.yaml"
    config_file.write_text("invalid: yaml: :")

    with (
        patch("edgewalker.core.config.get_config_dir", return_value=config_dir),
        patch("builtins.open", side_effect=Exception("Read error")),
    ):
        # Should not raise exception
        init_config()


def test_update_setting_device_id_error():
    """Test update_setting raising error for device_id."""
    with pytest.raises(AttributeError, match="device_id' setting is read-only"):
        update_setting("device_id", "new-id")


def test_update_setting_type_conversions(tmp_path):
    """Test type conversions in update_setting."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    with patch("edgewalker.core.config.get_config_dir", return_value=config_dir):
        # Test int conversion
        update_setting("api_timeout", "20")
        # First Party
        from edgewalker.core.config import settings

        assert settings.api_timeout == 20

        # Test bool conversion
        update_setting("telemetry_enabled", "true")
        assert settings.telemetry_enabled is True

        # Test Path conversion
        update_setting("cache_dir", "/tmp/new_cache")
        assert isinstance(settings.cache_dir, Path)
        assert str(settings.cache_dir) == "/tmp/new_cache"
