# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest


@pytest.fixture(autouse=True)
def global_telemetry_safety():
    """Ensure telemetry remains disabled and network calls remain mocked globally."""
    # First Party
    from edgewalker.core.config import settings

    # Reset telemetry and silent mode settings for every test
    settings.telemetry_enabled = False
    settings.silent_mode = False
    settings.suppress_warnings = False
    settings.accept_telemetry = False
    settings.decline_telemetry = False

    # Mock both sync and async httpx post calls globally
    with (
        patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_async_post,
        patch("httpx.Client.post") as mock_sync_post,
    ):
        mock_async_post.return_value = MagicMock(status_code=201)
        mock_sync_post.return_value = MagicMock(status_code=201)
        yield


@pytest.fixture
def mock_config_dir(tmp_path):
    """Fixture for a temporary config directory."""
    return tmp_path / "config"


@pytest.fixture
def mock_cache_dir(tmp_path):
    """Fixture for a temporary cache directory."""
    return tmp_path / "cache"


@pytest.fixture
def mock_output_dir(tmp_path):
    """Fixture for a temporary output directory."""
    return tmp_path / "scans"


@pytest.fixture
def settings_mock(tmp_path):
    # Standard Library
    from unittest.mock import MagicMock

    settings = MagicMock()
    settings.output_dir = tmp_path
    settings.telemetry_enabled = None
    settings.api_url = "http://test.api"
    settings.api_timeout = 5
    settings.category_weights = {"exposure": 0.25, "credentials": 0.40, "vulnerabilities": 0.35}
    settings.port_severity = {23: 80, 5900: 70, 21: 60, 22: 30}
    settings.port_severity_default = 10
    settings.port_extra_penalty = 3
    settings.cred_severity = {"telnet": 100, "ftp": 90, "smb": 85, "ssh": 80}
    settings.cred_severity_default = 80
    settings.cred_extra_penalty = 5
    settings.cve_severity = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
    settings.cve_severity_default = 25
    settings.cve_extra_penalty = 5
    return settings
