"""EdgeWalker TUI application -- main entry point."""

from __future__ import annotations

# Standard Library
import threading
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from loguru import Message

# Third Party
from textual.app import App
from textual.binding import Binding
from textual.command import CommandPalette, Hit, Provider
from textual.reactive import reactive
from textual.screen import Screen
from textual.style import Style

# First Party
from edgewalker import __version__
from edgewalker.core.config import settings, update_setting
from edgewalker.core.scanner_service import ScannerService
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.core.theme_manager import theme_manager
from edgewalker.modules.port_scan.scanner import check_nmap_permissions, fix_nmap_permissions
from edgewalker.theme import load_active_theme
from edgewalker.tui.modals.dialogs import (
    ConfirmModal,
    PermissionModal,
    TelemetryModal,
    UpdateModal,
)
from edgewalker.utils import check_for_updates, has_any_results, run_upgrade


class VersionProvider(Provider):
    """A command provider for version information."""

    async def discover(self) -> Iterable[Hit]:
        """Yield commands to show when the palette is first opened."""
        yield Hit(
            1,
            "Version",
            self.app.action_show_version,
            help="Show application version and Device ID",
        )

    async def search(self, query: str) -> Iterable[Hit]:
        """Search for version commands."""
        matcher = self.matcher(query)
        score = matcher.match("Version")
        if score > 0:
            yield Hit(
                score,
                matcher.highlight("Version"),
                self.app.action_show_version,
                help="Show application version and Device ID",
            )


class SettingsProvider(Provider):
    """A command provider for application settings."""

    async def discover(self) -> Iterable[Hit]:
        """Yield commands to show when the palette is first opened."""
        yield Hit(1, "Settings", self.app.action_settings, help="Manage EdgeWalker configuration")

    async def search(self, query: str) -> Iterable[Hit]:
        """Search for settings commands."""
        matcher = self.matcher(query)
        score = matcher.match("Settings")
        if score > 0:
            yield Hit(
                score,
                matcher.highlight("Settings"),
                self.app.action_settings,
                help="Manage EdgeWalker configuration",
            )


class ThemeProvider(Provider):
    """A command provider for switching themes."""

    def __init__(self, screen: Screen, match_style: Style, theme_only: bool = False) -> None:
        """Initialize the theme provider.

        Args:
            screen: The active screen.
            match_style: The style to use for matches.
            theme_only: If True, only show themes.
        """
        super().__init__(screen, match_style)
        self.theme_only = theme_only

    async def discover(self) -> Iterable[Hit]:
        """Yield commands to show when the palette is first opened."""
        if self.theme_only:
            # Get themes from manager
            themes = theme_manager.list_themes()
            # Sort to put periphery at the top
            themes.sort(key=lambda t: 0 if t["slug"] in ("periphery", "default") else 1)

            for theme_info in themes:
                name = "periphery" if theme_info["slug"] == "default" else theme_info["slug"]
                display_name = theme_info["name"]
                if theme_info["slug"] in ("periphery", "default"):
                    display_name = "Periphery EdgeWalker (Default)"

                yield Hit(
                    1,
                    display_name,
                    lambda t=name: self.app.action_set_theme(t),
                    help=f"Switch to {display_name} theme by {theme_info['author']}",
                )
        else:
            yield Hit(
                1, "Theme", self.app.action_theme_select, help="Change the application visual skin"
            )

    async def search(self, query: str) -> Iterable[Hit]:
        """Search for theme commands."""
        matcher = self.matcher(query)

        if self.theme_only:
            themes = theme_manager.list_themes()
            for theme_info in themes:
                name = "periphery" if theme_info["slug"] == "default" else theme_info["slug"]
                display_name = theme_info["name"]
                if theme_info["slug"] in ("periphery", "default"):
                    display_name = "Periphery EdgeWalker (Default)"

                score = matcher.match(display_name)
                if score > 0:
                    yield Hit(
                        score,
                        matcher.highlight(display_name),
                        lambda t=name: self.app.action_set_theme(t),
                        help=f"Switch to {display_name} theme by {theme_info['author']}",
                    )
        else:
            score = matcher.match("Theme")
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight("Theme"),
                    self.app.action_theme_select,
                    help="Change the application visual skin",
                )


class EdgeWalkerApp(App):
    """EdgeWalker Textual TUI application."""

    CSS_PATH = "css/edgewalker.tcss"
    TITLE = "EdgeWalker"
    SUB_TITLE = "IoT Security Scanner"

    BINDINGS = [
        Binding("q", "quit_app", "Quit", show=True),
    ]

    COMMANDS = App.COMMANDS | {SettingsProvider, ThemeProvider, VersionProvider}

    telemetry_status = reactive("idle")
    update_status = reactive("idle")
    has_nmap_permissions = reactive(True)

    def __init__(self, **kwargs: object) -> None:
        """Initialize the EdgeWalker application."""
        super().__init__(**kwargs)
        self.scanner = ScannerService(telemetry_callback=self._update_telemetry_status)
        self.is_scanning = False
        self.current_scan_target = ""
        self.scan_progress_log: list[tuple[str, str]] = []

        # Register all discovered themes
        for theme_info in theme_manager.list_themes():
            if textual_theme := theme_manager.load_textual_theme(theme_info["slug"]):
                self.register_theme(textual_theme)

        # Set initial theme (map 'default' to 'periphery')
        initial_theme = settings.theme
        if initial_theme == "default":
            initial_theme = "periphery"
        self.theme = initial_theme

    def on_mount(self) -> None:
        """Initialize the application on mount."""
        # Third Party
        from loguru import logger  # noqa: PLC0415

        # First Party
        from edgewalker.tui.screens.home import HomeScreen  # noqa: PLC0415

        # Add a log sink to redirect warnings/errors to TUI notifications
        def tui_log_sink(message: Message) -> None:
            record = message.record
            # Avoid notifying about the same thing multiple times if possible
            # or if it's too verbose. For now, just show warnings and errors.
            severity = record["level"].name.lower()
            msg = record["message"]

            def do_notify() -> None:
                self.notify(msg, severity=severity, timeout=10 if severity == "warning" else 15)

            self.call_from_thread(do_notify)

        logger.add(
            tui_log_sink,
            level="WARNING",
            filter=lambda r: r["level"].no >= 30,  # WARNING or higher
            format="{message}",
        )

        # Trigger validation for current settings to show warnings if any
        for warning in settings.get_security_warnings():
            self.notify(warning, severity="warning", timeout=10)

        self.telemetry = TelemetryManager(settings)

        # Set initial status
        if self.telemetry.settings.telemetry_enabled is False:
            self.telemetry_status = "disabled"

        # First-run telemetry notification
        if not self.telemetry.has_seen_telemetry_prompt():

            def on_dismiss(_: None) -> None:
                """Handle notification modal dismissal."""
                self.telemetry.set_telemetry_status(True)
                self._check_nmap_permissions()
                self._check_previous_results()
                self._check_config_overrides()
                self.run_worker(self._check_for_updates_async())

            self.push_screen(HomeScreen())
            self.push_screen(TelemetryModal(), on_dismiss)
        else:
            self.push_screen(HomeScreen())
            self._check_nmap_permissions()
            self._check_previous_results()
            self._check_config_overrides()
            self.run_worker(self._check_for_updates_async())

    async def _check_for_updates_async(self) -> None:
        """Check for updates in the background."""
        # Standard Library
        import asyncio  # noqa: PLC0415

        self.update_status = "checking"
        new_version = await asyncio.to_thread(check_for_updates)
        if new_version:
            self.update_status = "available"

            def on_update_choice(upgrade: bool) -> None:
                if upgrade:
                    with self.suspend():
                        run_upgrade(new_version)
                    self.exit()

            self.push_screen(UpdateModal(new_version), on_update_choice)
        else:
            self.update_status = "up-to-date"

    def _check_config_overrides(self) -> bool:
        """Check for configuration overrides and notify the user.

        Returns:
            True if overrides were detected, False otherwise.
        """
        # First Party
        from edgewalker.core.config import get_active_overrides  # noqa: PLC0415

        if overrides := get_active_overrides():
            sources = ", ".join(sorted(set(overrides.values())))
            self.notify(
                f"Configuration overrides active from {sources}. "
                "Some config.yaml settings may be ignored.",
                severity="warning",
                timeout=15,
            )
            return True
        return False

    def _check_nmap_permissions(self) -> None:
        """Check nmap permissions early and offer fix or unprivileged mode."""
        self.has_nmap_permissions = check_nmap_permissions()
        if self.has_nmap_permissions or settings.unprivileged:
            return

        def on_permission_choice(choice: str) -> None:
            if choice == "fix":
                with self.suspend():
                    success = fix_nmap_permissions()
                if success:
                    self.has_nmap_permissions = True
                    self.notify("Permissions fixed!")
                else:
                    self.notify("Failed to fix permissions.", severity="error")
            elif choice == "unprivileged":
                update_setting("unprivileged", True)
                self.notify("Switched to Unprivileged Mode (TCP Connect scans).")

        self.push_screen(PermissionModal(), on_permission_choice)

    def get_system_commands(self, screen: Screen) -> Iterable[Hit]:
        """Filter system commands to remove built-in theme switching."""
        yield from (
            command for command in super().get_system_commands(screen) if command.title != "Theme"
        )

    def watch_theme(self, theme: str) -> None:
        """React to theme changes."""
        if theme != settings.theme:
            try:
                update_setting("theme", theme)
                load_active_theme()

                # Force a full refresh of all screens to update Python-side constants
                for screen in self.screen_stack:
                    self.call_later(screen.recompose)

                self.notify(f"Theme changed to {theme}")
            except Exception as e:
                self.notify(f"Failed to save theme setting: {e}", severity="error")

    def action_settings(self) -> None:
        """Open the settings screen."""
        # First Party
        from edgewalker.tui.screens.config import ConfigScreen  # noqa: PLC0415

        self.push_screen(ConfigScreen())

    def action_show_version(self) -> None:
        """Show application version and Device ID."""
        self.notify(
            f"EdgeWalker v{__version__}\nDevice ID: {settings.device_id}",
            title="Version Info",
            timeout=10,
        )

    def action_theme_select(self) -> None:
        """Open a new command palette specifically for theme selection."""

        # Create a specialized provider class for this palette
        class ThemeOnlyProvider(ThemeProvider):
            def __init__(self, screen: Screen, match_style: Style) -> None:
                """Initialize the theme-only provider."""
                super().__init__(screen, match_style, theme_only=True)

        # Use call_later to ensure the current palette has closed before pushing a new one
        self.call_later(
            self.push_screen,
            CommandPalette(providers=[ThemeOnlyProvider], placeholder="Select a theme..."),
        )

    def action_set_theme(self, theme_slug: str | None) -> None:
        """Switch the application theme."""
        if not theme_slug:
            return
        self.theme = theme_slug

    def _check_previous_results(self) -> None:
        """If previous results exist, notify the user."""
        if has_any_results():
            self.notify(
                "Previous scan results detected. Use [9] to clear.",
                severity="warning",
                timeout=5,
            )

    def action_quit_app(self) -> None:
        """Global quit action with scan check."""
        if self.is_scanning:

            def check_confirm(confirmed: bool) -> None:
                if confirmed:
                    self.is_scanning = False
                    self.exit()

            # Use call_after_refresh to ensure the modal is pushed correctly
            self.call_after_refresh(
                lambda: self.push_screen(
                    ConfirmModal(
                        "QUIT EDGEWALKER?",
                        "A scan remains active. Quitting will terminate the current assessment.",
                    ),
                    check_confirm,
                )
            )
        else:
            self.exit()

    def notify_progress(self, event: str, data: str) -> None:
        """Store progress and notify active screen."""
        self.scan_progress_log.append((event, data))
        # If the active screen has an _on_progress method, call it
        if hasattr(self.screen, "_on_progress"):
            self.screen._on_progress(event, data)

    def _update_telemetry_status(self, status: str) -> None:
        """Update telemetry status reactive property safely."""
        if threading.current_thread() is threading.main_thread():
            self.telemetry_status = status
        else:
            self.call_from_thread(setattr, self, "telemetry_status", status)
