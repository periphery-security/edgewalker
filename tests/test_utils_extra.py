# Standard Library
import ipaddress
from datetime import datetime
from unittest.mock import patch

# Third Party
import pytest
import semver

# First Party
from edgewalker import utils
from edgewalker.core.config import settings


def test_json_serial():
    assert utils.json_serial(datetime(2026, 2, 28)) == "2026-02-28T00:00:00"
    assert utils.json_serial(ipaddress.IPv4Address("127.0.0.1")) == "127.0.0.1"
    assert utils.json_serial(semver.VersionInfo(1, 2, 3)) == "1.2.3"
    with pytest.raises(TypeError):
        utils.json_serial(object())


def test_save_results(tmp_path):
    settings.output_dir = tmp_path
    data = {"test": "data"}
    path = utils.save_results(data, "test.json")
    assert path.exists()
    # json.dump with indent=2 uses \n and spaces
    assert "test" in path.read_text()


def test_get_device_id():
    assert utils.get_device_id("00:11:22:33:44:55") == settings.device_id
    assert utils.get_device_id("") == settings.device_id


def test_has_port_scan(tmp_path):
    settings.output_dir = tmp_path
    assert utils.has_port_scan() is False
    (tmp_path / "port_scan.json").write_text("{}")
    assert utils.has_port_scan() is True


def test_get_scan_status(tmp_path):
    settings.output_dir = tmp_path
    status = utils.get_scan_status()
    assert status["port_scan"] is False

    (tmp_path / "port_scan.json").write_text('{"scan_type": "full", "hosts": [{"state": "up"}]}')
    status = utils.get_scan_status()
    assert status["port_scan"] is True
    assert status["port_scan_type"] == "full"
    assert status["devices_found"] == 1


def test_console_helpers():
    with patch("edgewalker.utils.console.print") as mock_print:
        utils.print_logo()
        utils.print_header("Test")
        utils.print_success("Success")
        utils.print_info("Info")
        utils.print_warning("Warning")
        utils.print_error("Error")
        assert mock_print.called


def test_get_input():
    with patch("edgewalker.utils.console.print"):
        with patch("builtins.input", return_value="test"):
            assert utils.get_input("Prompt") == "test"

        with patch("builtins.input", return_value=""):
            assert utils.get_input("Prompt", default="def") == "def"


def test_press_enter():
    with patch("edgewalker.utils.console.print"):
        with patch("builtins.input"):
            utils.press_enter()


def test_telemetry_helpers():
    with patch(
        "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt", return_value=True
    ):
        assert utils.has_seen_telemetry_prompt() is True

    with patch(
        "edgewalker.core.telemetry.TelemetryManager.is_telemetry_enabled", return_value=False
    ):
        assert utils.is_telemetry_enabled() is False


def test_get_progress():
    progress = utils.get_progress()
    assert progress.console == utils.console
