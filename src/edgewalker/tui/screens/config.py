"""EdgeWalker TUI configuration screen."""

from __future__ import annotations

# Standard Library
import contextlib

# Third Party
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    ContentSwitcher,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    Static,
    Switch,
)
from textual.widgets.option_list import Option

# First Party
from edgewalker.core.config import get_active_overrides, settings, update_setting
from edgewalker.core.theme_manager import theme_manager


class ConfigScreen(Screen):
    """Screen for managing application configuration."""

    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "Back", show=True),
        Binding("s", "save_and_exit", "Save & Exit", show=True),
    ]

    def _get_override_label(self, field_name: str) -> str:
        """Return an override label if the field is currently overridden.

        Args:
            field_name: The name of the configuration field.

        Returns:
            A formatted string indicating the override source, or an empty string.
        """
        overrides = get_active_overrides()
        env_key = f"EW_{field_name.upper()}"

        # Handle aliases
        field = settings.__class__.model_fields.get(field_name)
        alias = field.alias if field and field.alias else None

        if env_key in overrides:
            return f" [dim](overridden by {overrides[env_key]})[/dim]"
        if alias and alias in overrides:
            return f" [dim](overridden by {overrides[alias]})[/dim]"
        return ""

    def _get_security_warning_label(self, field_name: str) -> str:
        """Return a security warning label if the field has a non-standard value.

        Args:
            field_name: The name of the configuration field.

        Returns:
            A formatted string with a warning icon, or an empty string.
        """
        warnings = settings.get_security_warnings()
        field_label = field_name.replace("_", " ").upper()

        return next(
            (
                " [bold yellow]⚠[/bold yellow]"
                for warning in warnings
                if field_label in warning.upper()
            ),
            "",
        )

    def compose(self) -> ComposeResult:
        """Compose the configuration screen layout."""
        yield Header()
        with Horizontal(id="config-layout"):
            # Sidebar Navigation
            with Vertical(id="config-sidebar"):
                yield Static("SETTINGS", id="config-sidebar-title")
                yield OptionList(
                    Option("General", id="general"),
                    Option("Appearance", id="appearance"),
                    Option("API & External", id="api"),
                    Option("Scan Timeouts", id="timeouts"),
                    Option("Performance", id="performance"),
                    Option("Risk Scoring", id="risk"),
                    Option("Paths", id="paths"),
                    id="config-nav",
                )
                with Vertical(id="config-sidebar-bottom"):
                    yield Button(
                        "Save & Exit", variant="success", id="btn-save", classes="sidebar-btn"
                    )
                    yield Button("Cancel", variant="error", id="btn-cancel", classes="sidebar-btn")

            # Main Content Area
            with Vertical(id="config-main"):
                with ContentSwitcher(initial="general", id="config-switcher"):
                    # --- General Settings ---
                    with ScrollableContainer(id="general", classes="config-section"):
                        yield Label("GENERAL SETTINGS", classes="config-section-header")

                        with Horizontal(classes="config-row"):
                            yield Label(
                                f"Enable Telemetry{self._get_override_label('telemetry_enabled')}",
                                classes="config-label",
                            )
                            yield Switch(
                                value=settings.telemetry_enabled or False, id="telemetry_enabled"
                            )
                        yield Label(
                            "Share anonymous scan results to help improve IoT security.",
                            classes="config-help",
                        )

                        with Horizontal(classes="config-row"):
                            yield Label(
                                f"Unprivileged Mode{self._get_override_label('unprivileged')}",
                                classes="config-label",
                            )
                            yield Switch(value=settings.unprivileged, id="unprivileged")
                        yield Label(
                            "Run without sudo using TCP connect scans (macOS/no-root).",
                            classes="config-help",
                        )

                        with Horizontal(classes="config-row"):
                            yield Label("Device ID", classes="config-label")
                            yield Label(settings.device_id, id="device_id_label")
                        yield Label(
                            "Unique identifier for this installation (Read-only).",
                            classes="config-help",
                        )

                    # --- Appearance Settings ---
                    with ScrollableContainer(id="appearance", classes="config-section"):
                        yield Label("APPEARANCE", classes="config-section-header")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"Active Theme{self._get_override_label('theme')}",
                                classes="config-label",
                            )

                            themes = theme_manager.list_themes()
                            # Sort to put periphery at the top
                            themes.sort(
                                key=lambda t: 0 if t["slug"] in ["periphery", "default"] else 1
                            )

                            yield OptionList(
                                *[
                                    Option(f"{t['name']} (by {t['author']})", id=t["slug"])
                                    for t in themes
                                ],
                                id="theme_selector",
                            )
                        yield Label("Select the visual skin for EdgeWalker.", classes="config-help")

                    # --- API Settings ---
                    with ScrollableContainer(id="api", classes="config-section"):
                        yield Label("API & EXTERNAL SERVICES", classes="config-section-header")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"NVD API Key{self._get_override_label('nvd_api_key')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=settings.nvd_api_key or "",
                                placeholder="Enter NVD API Key",
                                id="nvd_api_key",
                            )
                        yield Label("Increases rate limits for CVE lookups.", classes="config-help")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"MAC Lookup API Key{self._get_override_label('mac_api_key')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=settings.mac_api_key or "",
                                placeholder="Enter MACLookup API Key",
                                id="mac_api_key",
                            )
                        yield Label(
                            "Increases rate limits for MAC vendor lookups (2 → 50 req/s).",
                            classes="config-help",
                        )

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"MAC Lookup API URL{self._get_override_label('mac_api_url')}"
                                f"{self._get_security_warning_label('mac_api_url')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=settings.mac_api_url,
                                placeholder="https://api.maclookup.app/v2/macs",
                                id="mac_api_url",
                            )

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"NVD API URL{self._get_override_label('nvd_api_url')}"
                                f"{self._get_security_warning_label('nvd_api_url')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=settings.nvd_api_url,
                                placeholder="https://services.nvd.nist.gov/...",
                                id="nvd_api_url",
                            )

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"EdgeWalker API URL{self._get_override_label('api_url')}"
                                f"{self._get_security_warning_label('api_url')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=settings.api_url,
                                placeholder="https://api.periphery.security/edgewalker/v1...",
                                id="api_url",
                            )

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"API Timeout (sec){self._get_override_label('api_timeout')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.api_timeout), placeholder="10", id="api_timeout"
                            )

                    # --- Scan Timeouts ---
                    with ScrollableContainer(id="timeouts", classes="config-section"):
                        yield Label("SCAN TIMEOUTS", classes="config-section-header")

                        with Horizontal(classes="config-row"):
                            yield Label(
                                f"Nmap Timeout (sec){self._get_override_label('nmap_timeout')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.nmap_timeout),
                                placeholder="900",
                                id="nmap_timeout",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Nmap Full Timeout (sec)"
                                f"{self._get_override_label('nmap_full_timeout')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.nmap_full_timeout),
                                placeholder="7200",
                                id="nmap_full_timeout",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Ping Sweep Timeout (sec)"
                                f"{self._get_override_label('ping_sweep_timeout')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.ping_sweep_timeout),
                                placeholder="300",
                                id="ping_sweep_timeout",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Connection Timeout (sec)"
                                f"{self._get_override_label('conn_timeout')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.conn_timeout), placeholder="5", id="conn_timeout"
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "NVD Rate Limit Delay (sec)"
                                f"{self._get_override_label('nvd_rate_limit_delay')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.nvd_rate_limit_delay),
                                placeholder="6",
                                id="nvd_rate_limit_delay",
                            )

                    # --- Performance ---
                    with ScrollableContainer(id="performance", classes="config-section"):
                        yield Label("PERFORMANCE", classes="config-section-header")

                        with Horizontal(classes="config-row"):
                            label_text = f"Scan Workers{self._get_override_label('scan_workers')}"
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.scan_workers), placeholder="4", id="scan_workers"
                            )
                        yield Label("Number of parallel nmap processes.", classes="config-help")

                        with Horizontal(classes="config-row"):
                            label_text = (
                                f"Credential Workers{self._get_override_label('cred_workers')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.cred_workers), placeholder="8", id="cred_workers"
                            )
                        yield Label(
                            "Number of concurrent threads for credential testing.",
                            classes="config-help",
                        )

                    # --- Risk Scoring ---
                    with ScrollableContainer(id="risk", classes="config-section"):
                        yield Label("RISK SCORING DEFAULTS", classes="config-section-header")

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Port Severity Default"
                                f"{self._get_override_label('port_severity_default')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.port_severity_default),
                                placeholder="10",
                                id="port_severity_default",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Port Extra Penalty"
                                f"{self._get_override_label('port_extra_penalty')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.port_extra_penalty),
                                placeholder="3",
                                id="port_extra_penalty",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Cred Severity Default"
                                f"{self._get_override_label('cred_severity_default')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.cred_severity_default),
                                placeholder="80",
                                id="cred_severity_default",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "Cred Extra Penalty"
                                f"{self._get_override_label('cred_extra_penalty')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.cred_extra_penalty),
                                placeholder="5",
                                id="cred_extra_penalty",
                            )

                        with Horizontal(classes="config-row"):
                            label_text = (
                                "CVE Severity Default"
                                f"{self._get_override_label('cve_severity_default')}"
                            )
                            yield Label(
                                label_text,
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.cve_severity_default),
                                placeholder="25",
                                id="cve_severity_default",
                            )

                        with Horizontal(classes="config-row"):
                            yield Label(
                                f"CVE Extra Penalty{self._get_override_label('cve_extra_penalty')}",
                                classes="config-label",
                            )
                            yield Input(
                                value=str(settings.cve_extra_penalty),
                                placeholder="5",
                                id="cve_extra_penalty",
                            )

                    # --- Paths ---
                    with ScrollableContainer(id="paths", classes="config-section"):
                        yield Label("PATHS", classes="config-section-header")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"Cache Directory{self._get_override_label('cache_dir')}",
                                classes="config-label",
                            )
                            yield Input(value=str(settings.cache_dir), id="cache_dir")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"Output Directory{self._get_override_label('output_dir')}",
                                classes="config-label",
                            )
                            yield Input(value=str(settings.output_dir), id="output_dir")

                        with Vertical(classes="config-row-v"):
                            yield Label(
                                f"Credentials File{self._get_override_label('creds_file')}",
                                classes="config-label",
                            )
                            yield Input(value=str(settings.creds_file), id="creds_file")

        yield Footer()

    def on_mount(self) -> None:
        """Set initial highlight for theme selector."""
        with contextlib.suppress(AttributeError, KeyError, IndexError):
            theme_selector = self.query_one("#theme_selector", OptionList)
            themes = theme_manager.list_themes()
            # Sort to match the compose order
            themes.sort(key=lambda t: 0 if t["slug"] in ["periphery", "default"] else 1)

            current_theme = settings.theme
            if current_theme == "default":
                current_theme = "periphery"

            for i, t in enumerate(themes):
                if t["slug"] == current_theme:
                    theme_selector.highlighted = i
                    break

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Switch the content area when a sidebar option is selected."""
        switcher = self.query_one("#config-switcher", ContentSwitcher)
        switcher.current = event.option.id

    def action_save_and_exit(self) -> None:
        """Save settings and return to previous screen."""
        try:
            # Collect and update all settings dynamically based on widget IDs
            simple_fields = [
                "telemetry_enabled",
                "unprivileged",
                "nvd_api_key",
                "mac_api_key",
                "nvd_api_url",
                "mac_api_url",
                "api_url",
                "api_timeout",
                "nmap_timeout",
                "nmap_full_timeout",
                "ping_sweep_timeout",
                "conn_timeout",
                "nvd_rate_limit_delay",
                "scan_workers",
                "cred_workers",
                "port_severity_default",
                "port_extra_penalty",
                "cred_severity_default",
                "cred_extra_penalty",
                "cve_severity_default",
                "cve_extra_penalty",
                "cache_dir",
                "output_dir",
                "creds_file",
            ]

            for field_name in simple_fields:
                try:
                    widget = self.query_one(f"#{field_name}")
                    if isinstance(widget, Switch):
                        value = widget.value
                    elif isinstance(widget, Input):
                        value = widget.value
                        # Handle empty strings for Optional fields
                        if field_name in ("nvd_api_key", "mac_api_key") and not value:
                            value = None

                    update_setting(field_name, value)
                except Exception as e:
                    self.app.notify(f"Error updating {field_name}: {e}", severity="error")

            # Handle theme selection separately
            try:
                theme_selector = self.query_one("#theme_selector", OptionList)
                if theme_selector.highlighted is not None:
                    selected_option = theme_selector.get_option_at_index(theme_selector.highlighted)
                    if selected_option.id != settings.theme:
                        self.app.theme = str(selected_option.id)
            except Exception as e:
                self.app.notify(f"Error updating theme: {e}", severity="error")

            self.app.notify("Settings saved successfully.")
            self.app.pop_screen()
        except Exception as e:
            self.app.notify(f"Unexpected error: {e}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-save":
            self.action_save_and_exit()
        elif event.button.id == "btn-cancel":
            self.app.pop_screen()
