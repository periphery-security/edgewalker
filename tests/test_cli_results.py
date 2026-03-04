# Standard Library
import json
from unittest.mock import patch

# First Party
from edgewalker.cli.results import ResultManager
from edgewalker.core.config import settings


def test_results_check_previous(tmp_path):
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    with patch("edgewalker.utils.get_input", return_value="y"):
        with patch.object(rm, "clear_results") as mock_clear:
            rm.check_previous_results()
            assert mock_clear.called


def test_results_clear(tmp_path):
    settings.output_dir = tmp_path
    f = tmp_path / "test.json"
    f.write_text("{}")

    rm = ResultManager()
    rm.clear_results(interactive=False)
    assert not f.exists()


def test_results_view_non_interactive(tmp_path):
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    with patch.object(rm, "_print_results_table") as mock_print:
        rm.view_results(interactive=False)
        assert mock_print.called


def test_results_view_interactive(tmp_path):
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    # Choice 0: Back
    with patch("edgewalker.utils.get_input", return_value="0"):
        rm.view_results(interactive=True)


def test_results_view_file(tmp_path):
    settings.output_dir = tmp_path
    f = tmp_path / "test.json"
    f.write_text(json.dumps({"key": "value"}))

    rm = ResultManager()
    with patch("edgewalker.utils.console.print_json") as mock_print:
        rm._view_file(f)
        assert mock_print.called
