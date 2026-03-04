#!/usr/bin/env python3
"""EdgeWalker - IoT Home Network Security Scanner.

A simple tool to assess security of home networks and IoT devices.
Scans for open ports, tests default credentials, and checks for known CVEs.

By Periphery (periphery.security)
"""

# Standard Library
import sys

# First Party
from edgewalker.cli import app
from edgewalker.core.config import init_config, settings
from edgewalker.modules import mac_lookup, password_scan
from edgewalker.tui.app import EdgeWalkerApp


def main() -> None:
    """Main entry point."""
    # Initialize the config file with defaults if it does not exist
    init_config()

    # Initialize cache directory and pass to modules
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    mac_lookup.init_cache(settings.cache_dir)
    password_scan.init_cache(settings.cache_dir)

    # If no arguments, launch TUI
    if len(sys.argv) == 1:
        try:
            EdgeWalkerApp().run()
        except KeyboardInterrupt:
            pass
    else:
        app()


if __name__ == "__main__":
    main()
