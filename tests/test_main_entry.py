# Standard Library
from unittest.mock import patch

# First Party
from edgewalker.main import main


def test_main_tui():
    with (
        patch("sys.argv", ["edgewalker"]),
        patch("edgewalker.tui.app.EdgeWalkerApp.run") as mock_run,
        patch("edgewalker.modules.mac_lookup.init_cache"),
        patch("edgewalker.modules.password_scan.init_cache"),
    ):
        main()
        assert mock_run.called


def test_main_cli():
    with (
        patch("sys.argv", ["edgewalker", "scan"]),
        patch("edgewalker.main.app") as mock_app,
        patch("edgewalker.modules.mac_lookup.init_cache"),
        patch("edgewalker.modules.password_scan.init_cache"),
        patch("builtins.input", return_value=""),
    ):
        main()

    assert mock_app.called


def test_main_keyboard_interrupt():
    with (
        patch("sys.argv", ["edgewalker"]),
        patch("edgewalker.tui.app.EdgeWalkerApp.run", side_effect=KeyboardInterrupt),
        patch("edgewalker.modules.mac_lookup.init_cache"),
        patch("edgewalker.modules.password_scan.init_cache"),
    ):
        main()  # Should not raise
