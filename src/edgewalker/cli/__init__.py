"""EdgeWalker CLI components."""

# Standard Library
import asyncio
from typing import Coroutine

# First Party
from edgewalker.cli.cli import app, interactive_mode
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner
from edgewalker.cli.menu import InteractiveMenu
from edgewalker.cli.results import ResultManager
from edgewalker.display import (
    build_credential_display,
    build_cve_display,
    build_mode_panel,
    build_port_scan_display,
    build_risk_report,
    build_scan_type_panel,
    build_status_panel,
    build_telemetry_panel,
)
from edgewalker.utils import (
    get_scan_status,
    has_any_results,
    has_port_scan,
    save_results,
)

__all__ = [
    "ScanController",
    "ResultManager",
    "GuidedScanner",
    "InteractiveMenu",
    "app",
    "interactive_mode",
    "build_port_scan_display",
    "build_credential_display",
    "build_cve_display",
    "build_mode_panel",
    "build_status_panel",
    "build_telemetry_panel",
    "save_results",
    "has_port_scan",
    "has_any_results",
    "get_scan_status",
    "build_risk_report",
    "build_scan_type_panel",
]


# Backward compatibility wrappers
def _run_async(coro: Coroutine[object, object, object]) -> object:
    """Run a coroutine in the current or a new event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        # This is problematic if we're already in a loop and want to run sync
        # But for tests it might be necessary.
        # In a real app, we shouldn't hit this if Typer commands are sync.
        return loop.run_until_complete(coro)


def automatic_mode(*args: object, **kwargs: object) -> object:
    """Wrapper for GuidedScanner.automatic_mode."""
    return _run_async(GuidedScanner(ScanController()).automatic_mode(*args, **kwargs))


def prompt_next_scan(*args: object, **kwargs: object) -> object:
    """Wrapper for GuidedScanner.prompt_next_scan."""
    return _run_async(GuidedScanner(ScanController()).prompt_next_scan(*args, **kwargs))


def run_port_scan(*args: object, **kwargs: object) -> object:
    """Wrapper for ScanController.run_port_scan."""
    return _run_async(ScanController().run_port_scan(*args, **kwargs))


def run_credential_scan(*args: object, **kwargs: object) -> object:
    """Wrapper for ScanController.run_credential_scan."""
    return _run_async(ScanController().run_credential_scan(*args, **kwargs))


def run_cve_scan(*args: object, **kwargs: object) -> object:
    """Wrapper for ScanController.run_cve_scan."""
    return _run_async(ScanController().run_cve_scan(*args, **kwargs))


def view_device_risk(*args: object, **kwargs: object) -> None:
    """Wrapper for ScanController.view_device_risk."""
    ScanController().view_device_risk(*args, **kwargs)
