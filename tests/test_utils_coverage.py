# Standard Library
import os
from unittest.mock import patch

# Third Party
import pytest

# First Party
from edgewalker.utils import (
    ensure_telemetry_choice,
    get_input,
    get_output_dir,
    json_serial,
    press_enter,
    print_logo,
)


def test_json_serial_error():
    """Test json_serial raising TypeError for unknown types."""
    with pytest.raises(TypeError, match="not serializable"):
        json_serial(set([1, 2, 3]))


def test_get_output_dir_demo_mode():
    """Test get_output_dir in demo mode."""
    with patch.dict(os.environ, {"EW_DEMO_MODE": "1"}):
        output_dir = get_output_dir()
        assert "demo_scans" in str(output_dir)


def test_print_logo_demo_and_overrides():
    """Test print_logo with demo mode and overrides."""
    with (
        patch.dict(os.environ, {"EW_DEMO_MODE": "1"}),
        patch("edgewalker.utils.get_active_overrides", return_value={"EW_THEME": "env"}),
        patch("edgewalker.utils.console.print") as mock_print,
    ):
        print_logo()
        # Check that it printed something about demo mode and overrides
        # We can't easily check the exact calls because of Rich objects,
        # but we can check that it was called multiple times.
        assert mock_print.call_count >= 3


def test_get_input_eof():
    """Test get_input handling EOFError."""
    with patch("builtins.input", side_effect=EOFError):
        assert get_input("Prompt", "default") == "default"


def test_press_enter_eof():
    """Test press_enter handling EOFError."""
    with patch("builtins.input", side_effect=EOFError):
        press_enter()  # Should not raise


def test_ensure_telemetry_choice_opt_in():
    """Test ensure_telemetry_choice with opt-in."""
    with (
        patch("edgewalker.utils.TelemetryManager.has_seen_telemetry_prompt", return_value=False),
        patch("edgewalker.utils.get_input", return_value="y"),
        patch("edgewalker.utils.TelemetryManager.set_telemetry_status") as mock_set,
        patch("edgewalker.utils.press_enter"),
        patch("edgewalker.utils.console.print"),
    ):
        ensure_telemetry_choice()
        mock_set.assert_called_once_with(True)


def test_ensure_telemetry_choice_opt_out():
    """Test ensure_telemetry_choice with opt-out."""
    with (
        patch("edgewalker.utils.TelemetryManager.has_seen_telemetry_prompt", return_value=False),
        patch("edgewalker.utils.get_input", return_value="n"),
        patch("edgewalker.utils.TelemetryManager.set_telemetry_status") as mock_set,
        patch("edgewalker.utils.press_enter"),
        patch("edgewalker.utils.console.print"),
    ):
        ensure_telemetry_choice()
        mock_set.assert_called_once_with(False)
