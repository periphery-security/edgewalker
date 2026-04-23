"""Tests for the auto-update check logic."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest
import semver

# First Party
from edgewalker import __version__
from edgewalker.utils import check_for_updates, get_upgrade_command


@pytest.fixture
def mock_settings():
    """Mock settings for update tests."""
    with patch("edgewalker.utils.settings") as mock:
        mock.auto_update_check = True
        mock.last_update_check = 0
        yield mock


@pytest.fixture
def mock_httpx():
    """Mock httpx for update tests."""
    with patch("httpx.get") as mock:
        yield mock


def test_check_for_updates_disabled(mock_settings):
    """Test that update check returns None when disabled."""
    mock_settings.auto_update_check = False
    assert check_for_updates() is None


def test_check_for_updates_too_soon(mock_settings):
    """Test that update check returns None when run too soon."""
    # Standard Library
    import time

    mock_settings.last_update_check = time.time() - 1000  # Less than 24h
    assert check_for_updates() is None


def test_check_for_updates_no_update(mock_settings, mock_httpx):
    """Test that update check returns None when no update is available."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"info": {"version": __version__}}
    mock_httpx.return_value = mock_response

    assert check_for_updates() is None


def test_check_for_updates_available(mock_settings, mock_httpx):
    """Test that update check returns version when update is available."""
    # Parse current version and increment it
    current = semver.VersionInfo.parse(__version__)
    next_version = str(current.bump_patch())

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"info": {"version": next_version}}
    mock_httpx.return_value = mock_response

    assert check_for_updates() == next_version


def test_check_for_updates_error(mock_settings, mock_httpx):
    """Test that update check returns None on error."""
    mock_httpx.side_effect = Exception("Network error")
    assert check_for_updates() is None


def test_get_upgrade_command_pipx():
    """Test upgrade command detection for pipx."""
    with patch("sys.executable", "/home/user/.local/pipx/venvs/edgewalker/bin/python"):
        assert get_upgrade_command() == ["pipx", "upgrade", "edgewalker"]


def test_get_upgrade_command_uv():
    """Test upgrade command detection for uv."""
    with patch("sys.executable", "/home/user/.local/share/uv/tools/edgewalker/bin/python"):
        assert get_upgrade_command() == ["uv", "tool", "upgrade", "edgewalker"]


def test_get_upgrade_command_pip():
    """Test upgrade command detection for standard pip/venv."""
    executable = "/usr/bin/python3"
    with patch("sys.executable", executable):
        assert get_upgrade_command() == [executable, "-m", "pip", "install", "-U", "edgewalker"]
