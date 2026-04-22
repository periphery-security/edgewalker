# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import httpx
import pytest

# First Party
from edgewalker.core.config import Settings
from edgewalker.core.telemetry import TelemetryManager


@pytest.fixture
def settings(tmp_path):
    return Settings(output_dir=tmp_path)


@pytest.fixture
def telemetry_manager(settings):
    return TelemetryManager(settings)


def test_get_session_id_new(telemetry_manager, tmp_path):
    session_id = telemetry_manager.get_session_id()
    assert len(session_id) == 32
    assert (tmp_path / "session_id").exists()
    assert (tmp_path / "session_id").read_text() == session_id


def test_get_session_id_existing(telemetry_manager, tmp_path):
    existing_id = "a" * 32
    (tmp_path / "session_id").write_text(existing_id)
    assert telemetry_manager.get_session_id() == existing_id


def test_is_telemetry_enabled_none(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = None
    assert telemetry_manager.is_telemetry_enabled() is True


def test_is_telemetry_enabled_true(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    assert telemetry_manager.is_telemetry_enabled() is True


def test_is_telemetry_enabled_migration(telemetry_manager, tmp_path):
    telemetry_manager.settings.telemetry_enabled = None
    (tmp_path / "optin").write_text("yes")
    with patch("edgewalker.core.telemetry.save_settings"):
        assert telemetry_manager.is_telemetry_enabled() is True
        assert telemetry_manager.settings.telemetry_enabled is True
        assert not (tmp_path / "optin").exists()


def test_set_telemetry_status(telemetry_manager):
    with patch("edgewalker.core.telemetry.save_settings") as mock_save:
        telemetry_manager.set_telemetry_status(True)
        assert telemetry_manager.settings.telemetry_enabled is True
        mock_save.assert_called_once()


def test_has_seen_telemetry_prompt(telemetry_manager, tmp_path):
    telemetry_manager.settings.telemetry_enabled = True
    assert telemetry_manager.has_seen_telemetry_prompt() is True

    telemetry_manager.settings.telemetry_enabled = None
    assert telemetry_manager.has_seen_telemetry_prompt() is False

    (tmp_path / "optin").write_text("no")
    assert telemetry_manager.has_seen_telemetry_prompt() is True


def test_anonymize_ip():
    assert TelemetryManager.anonymize_ip("192.168.1.1") == "192.168.0.0"
    assert TelemetryManager.anonymize_ip("invalid") == "invalid"


def test_anonymize_mac():
    assert TelemetryManager.anonymize_mac("00:11:22:33:44:55") == "00:11:22:00:00:00"
    assert TelemetryManager.anonymize_mac("00-11-22-33-44-55") == "00-11-22-00-00-00"
    assert TelemetryManager.anonymize_mac("invalid") == "invalid"
    assert TelemetryManager.anonymize_mac("") is None
    assert TelemetryManager.anonymize_mac(None) is None


def test_anonymize_scan_data(telemetry_manager):
    data = {
        "target": "192.168.1.0/24",
        "hosts": [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "router"},
            {"host": "192.168.1.2"},
        ],
    }
    anon = telemetry_manager.anonymize_scan_data(data)
    assert anon["target"] == "192.168.0.0/24"
    assert anon["hosts"][0]["ip"] == "192.168.0.0"
    assert anon["hosts"][0]["mac"] == "00:11:22:00:00:00"
    assert anon["hosts"][0]["hostname"] == ""
    assert anon["hosts"][1]["host"] == "192.168.0.0"


def test_anonymize_scan_data_single_ip(telemetry_manager):
    data = {"target": "192.168.1.1"}
    anon = telemetry_manager.anonymize_scan_data(data)
    assert anon["target"] == "192.168.0.0"


def test_anonymize_scan_data_redacted(telemetry_manager):
    data = {"target": "example.com"}
    anon = telemetry_manager.anonymize_scan_data(data)
    assert anon["target"] == "redacted"


@pytest.mark.asyncio
async def test_submit_scan_data_disabled(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = False
    res = await telemetry_manager.submit_scan_data("test", {})
    assert res is None


@pytest.mark.asyncio
async def test_submit_scan_data_success(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 201

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
        res = await telemetry_manager.submit_scan_data("test", {})
        assert res.status_code == 201


@pytest.mark.asyncio
async def test_submit_scan_data_retry(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response_429 = MagicMock(spec=httpx.Response)
    mock_response_429.status_code = 429
    mock_response_429.json.return_value = {"retry_after": 0.1}

    mock_response_201 = MagicMock(spec=httpx.Response)
    mock_response_201.status_code = 201

    with patch("httpx.AsyncClient.post", side_effect=[mock_response_429, mock_response_201]):
        with patch("asyncio.sleep", new_callable=AsyncMock):
            res = await telemetry_manager.submit_scan_data("test", {})
            assert res.status_code == 201


def test_submit_scan_data_sync_success(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 201

    with patch("httpx.Client.post", return_value=mock_response):
        res = telemetry_manager.submit_scan_data_sync("test", {})
        assert res.status_code == 201


def test_is_telemetry_enabled_migration_error(telemetry_manager, tmp_path):
    telemetry_manager.settings.telemetry_enabled = None
    (tmp_path / "optin").write_text("yes")
    with patch("pathlib.Path.read_text", side_effect=Exception("Read error")):
        assert telemetry_manager.is_telemetry_enabled() is True


@pytest.mark.asyncio
async def test_submit_scan_data_api_error(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 500

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
        res = await telemetry_manager.submit_scan_data("test", {})
        assert res.status_code == 500


@pytest.mark.asyncio
async def test_submit_scan_data_exception(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    with patch("httpx.AsyncClient.post", side_effect=Exception("Network error")):
        res = await telemetry_manager.submit_scan_data("test", {})
        assert res is None


def test_submit_scan_data_sync_retry(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response_429 = MagicMock(spec=httpx.Response)
    mock_response_429.status_code = 429
    mock_response_429.json.return_value = {"retry_after": 0.1}

    mock_response_201 = MagicMock(spec=httpx.Response)
    mock_response_201.status_code = 201

    with patch("httpx.Client.post", side_effect=[mock_response_429, mock_response_201]):
        with patch("time.sleep"):
            res = telemetry_manager.submit_scan_data_sync("test", {})
            assert res.status_code == 201


def test_submit_scan_data_sync_api_error(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 500

    with patch("httpx.Client.post", return_value=mock_response):
        res = telemetry_manager.submit_scan_data_sync("test", {})
        assert res.status_code == 500


def test_submit_scan_data_sync_exception(telemetry_manager):
    telemetry_manager.settings.telemetry_enabled = True
    with patch("httpx.Client.post", side_effect=Exception("Network error")):
        res = telemetry_manager.submit_scan_data_sync("test", {})
        assert res is None
