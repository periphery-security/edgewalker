# Standard Library
from unittest.mock import patch

# First Party
from edgewalker import main


def test_main_tui():
    with patch("sys.argv", ["edgewalker"]):
        with patch("edgewalker.main.EdgeWalkerApp.run") as mock_run:
            with patch("edgewalker.main.init_config"):
                with patch("pathlib.Path.mkdir"):
                    main.main()
                    assert mock_run.called


def test_main_cli():
    with patch("sys.argv", ["edgewalker", "scan"]):
        with patch("edgewalker.main.app") as mock_app:
            with patch("edgewalker.main.init_config"):
                with patch("pathlib.Path.mkdir"):
                    main.main()
                    assert mock_app.called
