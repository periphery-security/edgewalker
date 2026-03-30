"""Extra tests for ResultManager to improve coverage."""

# Standard Library
from pathlib import Path
from unittest.mock import patch

# First Party
from edgewalker.cli.results import ResultManager
from edgewalker.core.config import settings


def test_results_clear_no_dir(tmp_path):
    """Test clear_results when output_dir does not exist."""
    non_existent = tmp_path / "non_existent"
    settings.output_dir = non_existent

    rm = ResultManager()
    # Should return early without error
    rm.clear_results(interactive=False)


def test_results_clear_cancelled(tmp_path):
    """Test clear_results when user cancels."""
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    with patch("edgewalker.utils.get_input", return_value="n"):
        rm.clear_results(interactive=True)
        assert (tmp_path / "test.json").exists()


def test_results_clear_error(tmp_path):
    """Test clear_results when deletion fails."""
    settings.output_dir = tmp_path
    f = tmp_path / "test.json"
    f.write_text("{}")

    rm = ResultManager()
    with patch.object(Path, "unlink", side_effect=Exception("Permission denied")):
        rm.clear_results(interactive=False)
        assert f.exists()


def test_results_view_no_results_non_interactive(tmp_path):
    """Test view_results when no results exist (non-interactive)."""
    settings.output_dir = tmp_path

    rm = ResultManager()
    with patch("edgewalker.utils.has_any_results", return_value=False):
        rm.view_results(interactive=False)


def test_results_view_no_dir(tmp_path):
    """Test view_results when output_dir does not exist."""
    non_existent = tmp_path / "non_existent"
    settings.output_dir = non_existent

    rm = ResultManager()
    with patch("edgewalker.utils.has_any_results", return_value=True):
        rm.view_results(interactive=False)


def test_results_view_invalid_input(tmp_path):
    """Test view_results with invalid numeric input."""
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    # Choice "abc", then "" for "Press Enter", then "0" to exit
    with patch("edgewalker.utils.get_input", side_effect=["abc", "", "0"]):
        rm.view_results(interactive=True)


def test_results_view_out_of_range(tmp_path):
    """Test view_results with out of range index."""
    settings.output_dir = tmp_path
    (tmp_path / "test.json").write_text("{}")

    rm = ResultManager()
    # Choice "99", then "" for "Press Enter", then "0" to exit
    with patch("edgewalker.utils.get_input", side_effect=["99", "", "0"]):
        rm.view_results(interactive=True)


def test_results_table_sizes(tmp_path):
    """Test _print_results_table with different file sizes."""
    settings.output_dir = tmp_path

    f1 = tmp_path / "large.json"
    f1.write_text("x" * (2 * 1024 * 1024))  # 2 MB

    f2 = tmp_path / "medium.json"
    f2.write_text("x" * (2 * 1024))  # 2 KB

    rm = ResultManager()
    rm._print_results_table([f1, f2])


def test_view_file_error(tmp_path):
    """Test _view_file when reading fails."""
    f = tmp_path / "corrupt.json"
    f.write_text("invalid json")

    rm = ResultManager()
    rm._view_file(f)
