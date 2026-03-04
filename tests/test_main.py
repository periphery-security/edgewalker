# Standard Library
import os
import sys
from unittest.mock import patch

# First Party
from edgewalker.main import main


def test_main_tui_launch(tmp_path):
    """Test TUI launch when no arguments provided."""
    with patch.dict(
        os.environ,
        {"EW_CONFIG_DIR": str(tmp_path / "config"), "EW_CACHE_DIR": str(tmp_path / "cache")},
    ):
        with patch.object(sys, "argv", ["edgewalker"]):
            with patch("edgewalker.tui.app.EdgeWalkerApp.run") as mock_run:
                main()
                mock_run.assert_called_once()


def test_main_cli_launch(tmp_path):
    """Test CLI launch when arguments provided."""
    with patch.dict(
        os.environ,
        {"EW_CONFIG_DIR": str(tmp_path / "config"), "EW_CACHE_DIR": str(tmp_path / "cache")},
    ):
        with patch.object(sys, "argv", ["edgewalker", "scan"]):
            # Patch app where it is used in edgewalker.main
            with patch("edgewalker.main.app") as mock_app:
                # Mock input to avoid OSError in captured stdin
                with patch("builtins.input", return_value=""):
                    main()
                mock_app.assert_called_once()
