# Standard Library
from unittest.mock import MagicMock

# First Party
from edgewalker.core import logger_config


def test_custom_formatter():
    record_debug = {"level": MagicMock()}
    record_debug["level"].name = "DEBUG"
    fmt_debug = logger_config.custom_formatter(record_debug)
    # The formatter returns a string with <level> tags which loguru replaces
    assert "level" in fmt_debug

    record_info = {"level": MagicMock()}
    record_info["level"].name = "INFO"
    fmt_info = logger_config.custom_formatter(record_info)
    assert "level" in fmt_info


def test_setup_logging(tmp_path):
    log_file = str(tmp_path / "test.log")

    # Test verbosity 0
    logger_config.setup_logging(0, None)

    # Test verbosity 1
    logger_config.setup_logging(1, None)

    # Test verbosity 2 with log file
    logger_config.setup_logging(2, log_file)
    assert (tmp_path / "test.log").exists()
