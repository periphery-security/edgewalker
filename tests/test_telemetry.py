# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.core.telemetry import TelemetryManager


@pytest.fixture
def mock_settings(tmp_path):
    settings = MagicMock()
    settings.output_dir = tmp_path
    settings.telemetry_enabled = None
    settings.api_url = "http://test.api"
    settings.api_timeout = 5
    return settings


@pytest.fixture
def manager(mock_settings):
    return TelemetryManager(mock_settings)


def test_get_session_id(manager, tmp_path):
    sid1 = manager.get_session_id()
    assert len(sid1) == 32
    sid2 = manager.get_session_id()
    assert sid1 == sid2

    # Verify persistence
    session_file = tmp_path / "session_id"
    assert session_file.exists()
    assert session_file.read_text() == sid1


def test_telemetry_enabled_status(manager, mock_settings):
    assert manager.is_telemetry_enabled() is False

    with patch("edgewalker.core.telemetry.save_settings"):
        manager.set_telemetry_status(True)
        mock_settings.telemetry_enabled = True
        assert manager.is_telemetry_enabled() is True
        assert manager.has_seen_telemetry_prompt() is True


def test_anonymize_ip(manager):
    assert manager.anonymize_ip("192.168.1.10") == "192.168.0.0"
    assert manager.anonymize_ip("invalid") == "invalid"


def test_anonymize_mac(manager):
    assert manager.anonymize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:00:00:00"
    assert manager.anonymize_mac("AA-BB-CC-DD-EE-FF") == "AA-BB-CC-00-00-00"
    assert manager.anonymize_mac("") is None
    assert manager.anonymize_mac(None) is None


def test_anonymize_scan_data(manager):
    data = {
        "target": "192.168.1.0/24",
        "device_id": "old-id",
        "hosts": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "test"}],
        "results": [{"ip": "192.168.1.10"}],
    }
    anon = manager.anonymize_scan_data(data)
    assert anon["hosts"][0]["ip"] == "192.168.0.0"
    assert anon["hosts"][0]["hostname"] == ""
    assert anon["results"][0]["ip"] == "192.168.0.0"
    assert anon["target"] == "192.168.0.0/24"
    # Top-level device_id should be updated to settings.device_id
    assert anon["device_id"] == manager.settings.device_id


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_submit_scan_data(mock_post, manager, mock_settings):
    with patch("edgewalker.core.telemetry.save_settings"):
        mock_settings.telemetry_enabled = True
        mock_post.return_value.status_code = 201

        await manager.submit_scan_data("test", {"data": "val"})
        assert mock_post.called

        mock_post.reset_mock()
        mock_settings.telemetry_enabled = False
        await manager.submit_scan_data("test", {"data": "val"})
        assert not mock_post.called


@patch("httpx.Client.post")
def test_submit_scan_data_sync(mock_post, manager, mock_settings):
    with patch("edgewalker.core.telemetry.save_settings"):
        mock_settings.telemetry_enabled = True
        mock_post.return_value.status_code = 201

        manager.submit_scan_data_sync("test", {"data": "val"})
        assert mock_post.called
