# Standard Library
import json
from unittest.mock import patch

# First Party
from edgewalker import utils


def test_save_results(tmp_path):
    """Test saving results to JSON."""
    data = {"test": "data"}
    filename = "test.json"
    with patch("edgewalker.utils.settings") as mock_settings:
        mock_settings.output_dir = tmp_path
        path = utils.save_results(data, filename)
        assert path.exists()
        with open(path) as f:
            assert json.load(f) == data


def test_get_scan_status_empty(tmp_path):
    """Test status retrieval with no results."""
    with patch("edgewalker.utils.settings") as mock_settings:
        mock_settings.output_dir = tmp_path
        status = utils.get_scan_status()
        assert not status["port_scan"]
        assert status["devices_found"] == 0


def test_get_scan_status_populated(tmp_path):
    """Test status retrieval with existing results."""
    port_file = tmp_path / "port_scan.json"
    port_file.write_text(json.dumps({"scan_type": "quick", "hosts": [{"state": "up"}]}))

    with patch("edgewalker.utils.settings") as mock_settings:
        mock_settings.output_dir = tmp_path
        status = utils.get_scan_status()
        assert status["port_scan"]
        assert status["devices_found"] == 1


def test_print_helpers():
    with patch("edgewalker.utils.console.print") as mock_print:
        utils.print_success("msg")
        utils.print_info("msg")
        utils.print_warning("msg")
        utils.print_error("msg")
        assert mock_print.call_count == 4


@patch("builtins.input", return_value="test")
def test_get_input(mock_input):
    with patch("edgewalker.utils.settings") as mock_settings:
        mock_settings.silent_mode = False
        assert utils.get_input("prompt") == "test"
        assert utils.get_input("prompt", "default") == "test"


@patch("builtins.input", return_value="")
def test_get_input_default(mock_input):
    with patch("edgewalker.utils.settings") as mock_settings:
        mock_settings.silent_mode = False
        assert utils.get_input("prompt", "default") == "default"


def test_is_physical_mac():
    """Test physical MAC detection."""
    # Physical MACs (second digit not 2, 6, A, E)
    assert utils.is_physical_mac("00:11:22:33:44:55") is True
    assert utils.is_physical_mac("B4:2E:99:11:22:33") is True
    assert utils.is_physical_mac("01:00:5E:00:00:01") is True  # Multicast but not LAA

    # Virtual/Randomized MACs (LAA bit set)
    assert utils.is_physical_mac("02:11:22:33:44:55") is False
    assert utils.is_physical_mac("16:11:22:33:44:55") is False
    assert utils.is_physical_mac("AA:11:22:33:44:55") is False
    assert utils.is_physical_mac("EE:11:22:33:44:55") is False

    # Invalid MACs
    assert utils.is_physical_mac("") is False
    assert utils.is_physical_mac("short") is False
    assert utils.is_physical_mac("too:long:mac:address:here") is False


def test_get_device_id():
    """Test device ID generation."""
    # First Party
    from edgewalker.core.config import settings

    # Should always return settings.device_id regardless of input
    assert utils.get_device_id("00:11:22:33:44:55") == settings.device_id
    assert utils.get_device_id(["00:11:22:33:44:55", "B4:2E:99:11:22:33"]) == settings.device_id
    assert utils.get_device_id([]) == settings.device_id
    assert utils.get_device_id("") == settings.device_id
