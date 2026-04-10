"""EdgeWalker Utilities.

Console helpers, file I/O, and shared state used across the application.
"""

# Standard Library
import contextlib
import ipaddress
import json
import os
from datetime import datetime
from pathlib import Path

# Third Party
import semver
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

# First Party
from edgewalker import theme
from edgewalker.core.config import get_active_overrides, settings
from edgewalker.core.telemetry import TelemetryManager

# Rich console — single instance shared across the application

console = Console()

# Re-export commonly used paths


def json_serial(obj: object) -> str:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(obj)
    if isinstance(obj, semver.VersionInfo):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


def get_output_dir() -> Path:
    """Return the active output directory, accounting for demo mode."""
    output_dir = settings.output_dir
    if os.environ.get("EW_DEMO_MODE") == "1":
        return output_dir.parent / "demo_scans"
    return output_dir


def save_results(data: dict, filename: str) -> Path:
    """Save results to JSON file with restricted permissions."""
    output_dir = get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_dir, 0o700)
    output_path = output_dir / filename

    # Open with restricted permissions (0o600: read/write for owner only)
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, default=json_serial)

    return output_path


def is_physical_mac(mac: str) -> bool:
    """Check if a MAC address is likely a physical (globally unique) address.

    Filters out virtual/randomized addresses by checking the Locally
    Administered Address (LAA) bit.
    """
    if not mac:
        return False
    # Normalize MAC
    clean_mac = "".join(c for c in mac if c.isalnum()).upper()
    if len(clean_mac) != 12:
        return False

    # Check Locally Administered Address (LAA) bit
    # The second hex digit (bits 1-4 of the first byte) indicates LAA if bit 1 is set.
    # Hex digits with bit 1 set: 2, 3, 6, 7, A, B, E, F
    second_digit = clean_mac[1]
    return second_digit not in "2367ABEF"


def get_device_id(macs: str | list[str] | None = None) -> str:
    """Return the persistent unique identifier for this installation."""
    return settings.device_id


def has_port_scan() -> bool:
    """Check if port scan results exist."""
    return (get_output_dir() / "port_scan.json").exists()


def has_any_results() -> bool:
    """Check if any results exist."""
    output_dir = get_output_dir()
    return output_dir.exists() and any(output_dir.glob("*.json"))


def get_scan_status() -> dict:
    """Get status of all scans."""
    status = {
        "port_scan": False,
        "port_scan_type": None,
        "password_scan": False,
        "cve_scan": False,
        "sql_scan": False,
        "web_scan": False,
        "devices_found": 0,
        "vulnerable_devices": 0,
        "cves_found": 0,
        "sql_vulns": 0,
        "web_vulns": 0,
    }

    output_dir = get_output_dir()
    port_file = output_dir / "port_scan.json"
    if port_file.exists():
        try:
            with open(port_file) as f:
                data = json.load(f)
            status["port_scan"] = True
            status["port_scan_type"] = data.get("scan_type", "quick")
            status["devices_found"] = len([
                h for h in data.get("hosts", []) if h.get("state") == "up"
            ])
        except (PermissionError, json.JSONDecodeError):
            pass

    pwd_file = output_dir / "password_scan.json"
    if pwd_file.exists():
        try:
            with open(pwd_file) as f:
                data = json.load(f)
            status["password_scan"] = True
            status["vulnerable_devices"] = data.get("summary", {}).get("vulnerable_hosts", 0)
        except (PermissionError, json.JSONDecodeError):
            pass

    cve_file = output_dir / "cve_scan.json"
    if cve_file.exists():
        try:
            with open(cve_file) as f:
                data = json.load(f)
            status["cve_scan"] = True
            status["cves_found"] = data.get("summary", {}).get("total_cves", 0)
        except (PermissionError, json.JSONDecodeError):
            pass

    sql_file = output_dir / "sql_scan.json"
    if sql_file.exists():
        try:
            with open(sql_file) as f:
                data = json.load(f)
            status["sql_scan"] = True
            status["sql_vulns"] = data.get("summary", {}).get("vulnerable_services", 0)
        except (PermissionError, json.JSONDecodeError):
            pass

    web_file = output_dir / "web_scan.json"
    if web_file.exists():
        try:
            with open(web_file) as f:
                data = json.load(f)
            status["web_scan"] = True
            status["web_vulns"] = data.get("summary", {}).get("vulnerable_headers", 0) + data.get(
                "summary", {}
            ).get("sensitive_files_found", 0)
        except (PermissionError, json.JSONDecodeError):
            pass

    return status


# ── Console output helpers ────────────────────────────────────────────────


def print_logo() -> None:
    """Print the EdgeWalker logo with gradient coloring."""
    logo_text = theme.gradient_text(theme.LOGO)
    console.print(logo_text)

    # Force tagline to align with logo (approx 60 chars)
    width = 50
    pad = width - len(theme.TAGLINE)
    console.print(f"[dim {theme.ACCENT}]{' ' * pad}{theme.TAGLINE}[/dim {theme.ACCENT}]")
    console.print()

    # Check for configuration overrides and notify user prominently
    overrides = get_active_overrides()
    is_demo = os.environ.get("EW_DEMO_MODE") == "1"

    if is_demo:
        console.print(
            Panel(
                f"[bold {theme.RISK_CRITICAL}]⚠ DEMO MODE ACTIVE ⚠[/bold {theme.RISK_CRITICAL}]\n"
                "[dim]EdgeWalker is running with mock data. No real scanning is being performed.\n"
                "Results are simulated and saved to a separate demo directory.[/dim]",
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        console.print()

    if overrides and not settings.suppress_warnings:
        sources = ", ".join(sorted(set(overrides.values())))
        keys = ", ".join(sorted(overrides.keys()))
        console.print(
            Panel(
                f"[bold {theme.WARNING}]CONFIGURATION OVERRIDES ACTIVE[/bold {theme.WARNING}]\n"
                f"[dim]Settings overridden by {sources}:[/dim]\n"
                f"[cyan]{keys}[/cyan]\n\n"
                f"[dim]Run [bold]edgewalker config show[/bold] to see details.[/dim]",
                border_style=theme.WARNING,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        console.print()


def clear_screen() -> None:
    """Clear the terminal screen."""
    console.clear()


def print_header(title: str) -> None:
    """Print a section header."""
    console.print()
    console.print(
        Panel(
            f"[{theme.HEADER}]{title}[/{theme.HEADER}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
            width=theme.get_ui_width(),
        )
    )


def print_success(msg: str) -> None:
    """Print success message."""
    console.print(f"[{theme.SUCCESS}]{theme.ICON_CHECK}[/{theme.SUCCESS}] {msg}")


def print_info(msg: str) -> None:
    """Print info message."""
    console.print(f"[{theme.SECONDARY}]{theme.ICON_SCAN}[/{theme.SECONDARY}] {msg}")


def print_warning(msg: str) -> None:
    """Print warning message."""
    console.print(f"[{theme.WARNING}]{theme.ICON_WARN}[/{theme.WARNING}] {msg}")


def print_error(msg: str) -> None:
    """Print error message."""
    console.print(f"[{theme.DANGER}]{theme.ICON_FAIL}[/{theme.DANGER}] {msg}")


def get_input(prompt: str, default: str = None) -> str:
    """Get user input with optional default."""
    if settings.silent_mode:
        return default

    if default:
        prompt_text = (
            f"[{theme.PRIMARY}]{theme.ICON_ARROW} {prompt}[/{theme.PRIMARY}] "
            f"[{theme.MUTED}][{default}][/{theme.MUTED}]: "
        )
    else:
        prompt_text = f"[{theme.PRIMARY}]{theme.ICON_ARROW} {prompt}[/{theme.PRIMARY}]: "

    console.print(prompt_text, end="")
    try:
        value = input().strip()
    except EOFError:
        return default
    return value or default


def press_enter() -> None:
    """Wait for user to press enter."""
    if settings.silent_mode:
        return

    console.print()
    console.print(f"[{theme.MUTED}]Press Enter to continue...[/{theme.MUTED}]", end="")
    with contextlib.suppress(EOFError):
        input()


def has_seen_telemetry_prompt() -> bool:
    """Check if the user has seen the opt-in prompt."""
    return TelemetryManager(settings).has_seen_telemetry_prompt()


def is_telemetry_enabled() -> bool:
    """Get the user's opt-in status."""
    return TelemetryManager(settings).is_telemetry_enabled()


def ensure_telemetry_choice() -> None:
    """Ensure the user has seen the telemetry opt-in prompt and made a choice."""
    telemetry = TelemetryManager(settings)

    # Handle silent mode flags first
    if settings.accept_telemetry:
        telemetry.set_telemetry_status(True)
        return
    if settings.decline_telemetry:
        telemetry.set_telemetry_status(False)
        return

    if not telemetry.has_seen_telemetry_prompt():
        if settings.silent_mode:
            # Third Party
            import typer  # noqa: PLC0415

            console.print()
            console.print(
                Panel(
                    f"[bold {theme.DANGER}]ERROR: Telemetry choice required in silent mode."
                    f"[/bold {theme.DANGER}]\n\n"
                    "When running with [bold]--silent[/bold], you must explicitly provide a "
                    "telemetry choice if one has not been set yet.\n\n"
                    "Use [bold]--accept-telemetry[/bold] to opt-in or "
                    "[bold]--decline-telemetry[/bold] to opt-out.",
                    border_style=theme.DANGER,
                    box=theme.BOX_STYLE,
                    width=theme.get_ui_width(),
                )
            )
            raise typer.Exit(code=1)

        # First Party
        from edgewalker.display import build_telemetry_panel  # noqa: PLC0415

        console.print()
        console.print(build_telemetry_panel())
        console.print()

        choice = get_input("Share anonymous data to help secure IoT devices? [Y/n]", "y")
        opted_in = choice.lower() != "n"
        telemetry.set_telemetry_status(opted_in)

        if opted_in:
            console.print()
            console.print(
                f"[{theme.SUCCESS}]{theme.ICON_CHECK} Thank you! Your anonymous contributions "
                f"will help secure IoT devices worldwide.[/{theme.SUCCESS}]"
            )
        else:
            console.print()
            console.print(
                f"[{theme.MUTED_STYLE}]No problem. You can change this later in your "
                f"config file: {settings.model_config.get('yaml_file')}[/{theme.MUTED_STYLE}]"
            )

        press_enter()


def get_progress() -> Progress:
    """Return a themed Rich Progress object for CLI scans."""
    return Progress(
        SpinnerColumn(style=theme.ACCENT),
        TextColumn(f"[bold {theme.PRIMARY}]{{task.description}}"),
        BarColumn(
            bar_width=30,
            style=theme.MUTED,
            complete_style=theme.ACCENT,
            finished_style=theme.SUCCESS,
        ),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
