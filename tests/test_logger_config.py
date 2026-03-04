# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
from loguru import logger

# First Party
from edgewalker.core.logger_config import custom_formatter, setup_logging


def test_custom_formatter_debug():
    record = {"level": MagicMock()}
    record["level"].name = "DEBUG"
    fmt = custom_formatter(record)
    assert "{name}" in fmt
    assert "{function}" in fmt
    assert "{line}" in fmt


def test_custom_formatter_info():
    record = {"level": MagicMock()}
    record["level"].name = "INFO"
    fmt = custom_formatter(record)
    assert "{level: <8}" in fmt
    assert "{name}" not in fmt


def test_setup_logging_verbosity_0():
    with patch.object(logger, "remove") as mock_remove:
        with patch.object(logger, "add") as mock_add:
            setup_logging(0, None)
            mock_remove.assert_called_once()
            # Check if add was called for RichHandler
            assert mock_add.call_count == 1
            args, kwargs = mock_add.call_args
            assert kwargs["level"] == "WARNING"


def test_setup_logging_verbosity_1():
    with patch.object(logger, "remove") as mock_remove:
        with patch.object(logger, "add") as mock_add:
            setup_logging(1, None)
            args, kwargs = mock_add.call_args
            assert kwargs["level"] == "INFO"


def test_setup_logging_verbosity_2():
    with patch.object(logger, "remove") as mock_remove:
        with patch.object(logger, "add") as mock_add:
            setup_logging(2, None)
            args, kwargs = mock_add.call_args
            assert kwargs["level"] == "DEBUG"


def test_setup_logging_with_file():
    with patch.object(logger, "remove") as mock_remove:
        with patch.object(logger, "add") as mock_add:
            setup_logging(1, "test.log")
            assert mock_add.call_count == 2
            # Second call should be for the file
            args, kwargs = mock_add.call_args_list[1]
            assert args[0] == "test.log"
            assert kwargs["level"] == "DEBUG"
            assert kwargs["rotation"] == "10 MB"
