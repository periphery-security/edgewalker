"""EdgeWalker Logging Configuration.

Configures Loguru for console and file output with custom formatting.
"""

# Standard Library
from typing import Any, Dict, Optional

# Third Party
from loguru import logger
from rich.logging import RichHandler


def custom_formatter(record: Dict[str, Any]) -> str:
    """Custom loguru formatter that changes format based on log level.

    - DEBUG level includes the level name.
    - INFO and higher levels omit the level name for brevity.

    Args:
        record: The log record dictionary.

    Returns:
        The format string for the record.
    """
    time_format = "<green>{time:YYYY-MM-DD HH:mm:ss}</green>"
    level_format = "<level>{level: <8}</level>"
    source_format = "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan>"
    message_format = "<level>{message}</level>"

    # Keep full details for DEBUG, simplify otherwise
    log_format = (
        f"{time_format} | {level_format} | {source_format} - {message_format}\\n"
        if record["level"].name == "DEBUG"
        else f"{time_format} | {level_format} | {message_format}\\n"
    )
    # Ensure the format ends with a newline character
    return log_format if log_format.endswith("\\n") else log_format + "\\n"


def setup_logging(verbosity: int, log_file: Optional[str]) -> None:
    """Configures the Loguru logger sinks and formatting.

    Formatting is based on verbosity and an optional log file path.

    Args:
        verbosity: Verbosity level (0=WARNING, 1=INFO, 2+=DEBUG).
        log_file: Path to the log file, if any.
    """
    logger.remove()  # Remove default handler

    # Determine log level based on verbosity
    if verbosity == 0:
        log_level = "WARNING"
    elif verbosity == 1:
        log_level = "INFO"
    else:  # verbosity >= 2
        log_level = "DEBUG"

    # --- Configure Console Sink using RichHandler ---
    logger.add(
        RichHandler(
            level=log_level,  # Set level directly on the handler
            show_path=False,  # Don't show the full file path
            markup=True,  # Enable Rich markup in log messages
            show_time=True,  # Show timestamp (RichHandler default)
            show_level=True,  # Show level name (RichHandler default)
        ),
        level=log_level,  # Also set level for Loguru filtering
        format="{message}",  # Let RichHandler do the formatting
    )
    # --- End Console Sink Configuration ---

    # Configure file sink if log_file is provided (remains the same)
    if log_file:
        # Keep original file formatting or use a simple one
        file_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        logger.add(
            log_file,
            level="DEBUG",  # Log everything to the file
            format=file_format,  # Use a standard Loguru format for the file
            colorize=False,
            rotation="10 MB",
            retention="7 days",
        )
        # Log info message *after* potentially adding the file handler
        logger.info(f"Logging to file: {log_file}")

    logger.debug(
        f"Logging setup complete. Console level: {log_level}, "
        f"File logging active: {'Yes' if log_file else 'No'}"
    )
