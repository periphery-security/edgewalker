# Standard Library
import os
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.core.config import settings
from edgewalker.core.telemetry import TelemetryManager


def test_telemetry_session_id(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        settings.output_dir = tmp_path
        tm = TelemetryManager(settings)
        session_id = tm.get_session_id()
        assert len(session_id) == 32
        assert tm.get_session_id() == session_id


def test_telemetry_enabled(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        settings.output_dir = tmp_path
        settings.telemetry_enabled = None
        tm = TelemetryManager(settings)
        assert tm.is_telemetry_enabled() is False

        tm.set_telemetry_status(True)
        assert tm.is_telemetry_enabled() is True


def test_telemetry_anonymize():
    tm = TelemetryManager(settings)
    assert tm.anonymize_ip("192.168.1.100") == "192.168.0.0"
    assert tm.anonymize_mac("00:11:22:33:44:55") == "00:11:22:00:00:00"

    data = {
        "hosts": [{"ip": "10.0.0.1", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "secret"}],
        "target": "10.0.0.0/24",
    }
    anon = tm.anonymize_scan_data(data)
    assert anon["hosts"][0]["ip"] == "10.0.0.0"
    assert anon["hosts"][0]["mac"] == "AA:BB:CC:00:00:00"
    assert anon["hosts"][0]["hostname"] == ""
    assert anon["target"] == "10.0.0.0/24"


@pytest.mark.asyncio
async def test_telemetry_submit_async(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        tm = TelemetryManager(settings)
        tm.set_telemetry_status(True)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            await tm.submit_scan_data("test", {"data": "val"})
            assert mock_post.called


def test_telemetry_submit_sync(tmp_path):
    with patch.dict(os.environ, {"EW_CONFIG_DIR": str(tmp_path)}):
        tm = TelemetryManager(settings)
        tm.set_telemetry_status(True)

        with patch("httpx.Client.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=201)
            tm.submit_scan_data_sync("test", {"data": "val"})
            assert mock_post.called
