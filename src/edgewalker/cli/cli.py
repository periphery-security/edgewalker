"""EdgeWalker CLI — Command-line and interactive menu interfaces.

Handles Typer CLI mode, automatic guided mode, and the manual
interactive menu.
"""

# Standard Library
import asyncio
import importlib.metadata
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Optional

# Third Party
import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

# First Party
from edgewalker import __version__, theme
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner
from edgewalker.cli.menu import InteractiveMenu
from edgewalker.cli.results import ResultManager
from edgewalker.core.config import (
    CONFIG_DIR,
    get_active_overrides,
    settings,
    update_setting,
)
from edgewalker.core.logger_config import setup_logging
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.utils import (
    console,
    ensure_telemetry_choice,
    print_logo,
)

# ============================================================================
# TYPER APP SETUP
# ============================================================================

app = typer.Typer(
    help="EdgeWalker - IoT Home Network Security Scanner",
    no_args_is_help=False,  # We handle no args in main.py to launch TUI
    rich_markup_mode="rich",
)

config_app = typer.Typer(help="Manage EdgeWalker configuration.")
app.add_typer(config_app, name="config")

# ============================================================================
# CONFIG COMMANDS
# ============================================================================


@config_app.command("show")
def config_show() -> None:
    """Show current configuration settings."""
    print_logo()
    table = Table(box=box.SIMPLE)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Description", style="dim")

    # Filter out internal/complex fields for display
    skip_fields = {
        "iot_ports",
        "category_weights",
        "port_severity",
        "cred_severity",
        "cve_severity",
    }

    # Add device_id explicitly at the top
    table.add_row(
        "device_id", settings.device_id, "Unique identifier for this installation (Read-only)"
    )

    overrides = get_active_overrides()

    for name in settings.model_fields:
        if name in skip_fields or name == "device_id":
            continue

        info = settings.get_field_info(name)
        value = info["value"]
        description = settings.model_fields[name].description or ""

        display_value = str(value)
        if info["is_overridden"]:
            display_value = f"[yellow]{value}[/yellow] [dim](via {info['override_source']})[/dim]"
        elif info["is_modified"]:
            display_value = f"[yellow]{value}[/yellow] [dim](modified in config.yaml)[/dim]"

        display_name = name
        if info["security_warning"]:
            display_name = f"[bold yellow]⚠[/bold yellow] {name}"

        table.add_row(display_name, display_value, description)

    console.print(
        Panel(
            table,
            title=f"[{theme.HEADER}]EDGEWALKER CONFIGURATION[/{theme.HEADER}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
            width=theme.get_ui_width(),
        )
    )
    console.print(f"\n[dim]Config file: {CONFIG_DIR / 'config.yaml'}[/dim]")
    if overrides:
        sources = ", ".join(sorted(set(overrides.values())))
        console.print(
            f"[yellow]Note: Some settings are currently overridden by {sources}.[/yellow]"
        )

    # Add security warnings
    security_warnings = settings.get_security_warnings()
    if security_warnings:
        console.print(
            f"\n[bold {theme.RISK_CRITICAL}]SECURITY WARNINGS:[/bold {theme.RISK_CRITICAL}]"
        )
        for warning in security_warnings:
            console.print(f"  [bold yellow]⚠[/bold yellow] {warning}")


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    """Update a configuration setting."""
    try:
        update_setting(key, value)
        console.print(f"[green]Successfully updated {key} to {value}[/green]")
    except AttributeError as e:
        console.print(f"[red]Error: {e}[/red]")
    except ValueError:
        console.print(f"[red]Error: Invalid value for {key}[/red]")


@config_app.command("path")
def config_path() -> None:
    """Print the path to the configuration file."""
    console.print(str(CONFIG_DIR / "config.yaml"))


# ============================================================================
# TYPER COMMANDS
# ============================================================================


@app.command("scan")
def run_guided_scan(
    full: bool = typer.Option(False, "--full", help="Perform a full port scan (all 65535 ports)."),
    full_creds: bool = typer.Option(
        False, "--full-creds", help="Perform a thorough credential scan (all ~170 credentials)."
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target IP address or range."
    ),
    allow_override: bool = typer.Option(
        False,
        "--allow-override",
        "-ao",
        help="Allow scan to proceed with active configuration overrides.",
    ),
) -> None:
    """Run a guided security scan.

    This sequentially performs a port scan, credential check, and CVE check,
    then generates a final security report.
    """
    print_logo()

    # Check for security warnings and overrides
    security_warnings = settings.get_security_warnings()
    overrides = get_active_overrides()

    if (security_warnings or overrides) and not allow_override:
        if security_warnings and not settings.suppress_warnings:
            console.print(
                f"\n[bold {theme.RISK_CRITICAL}]SECURITY WARNING: "
                f"Non-standard or insecure API endpoints detected![/bold {theme.RISK_CRITICAL}]"
            )
            for warning in security_warnings:
                console.print(f"  [bold yellow]⚠[/bold yellow] {warning}")
            console.print(
                "\n[dim]Ensure you trust these endpoints as they may receive "
                "sensitive data like API keys.[/dim]"
            )

        if overrides and not settings.suppress_warnings:
            sources = ", ".join(sorted(set(overrides.values())))
            console.print(
                f"\n[bold {theme.WARNING}]CONFIGURATION OVERRIDES ACTIVE "
                f"from {sources}[/bold {theme.WARNING}]"
            )
            for key, source in sorted(overrides.items()):
                console.print(f"  [cyan]• {key}[/cyan] [dim](via {source})[/dim]")
            console.print(
                "\n[dim]These settings will take precedence over your config.yaml file.[/dim]"
            )

        if not settings.silent_mode:
            console.print("")
            confirm = typer.confirm("Do you want to proceed with the scan using these settings?")
            if not confirm:
                console.print(
                    "\n[dim]Scan cancelled. Use [bold]--allow-override[/bold] or "
                    "[bold]-ao[/bold] to bypass this check.[/dim]"
                )
                raise typer.Exit()
        elif (security_warnings or overrides) and not settings.suppress_warnings:
            console.print("")
            console.print(
                f"[{theme.WARNING}]Silent mode active: proceeding with scan "
                f"despite security warnings.[/{theme.WARNING}]"
            )

    ensure_telemetry_choice()
    controller = ScanController()
    guided = GuidedScanner(controller)
    asyncio.run(guided.automatic_mode(full_scan=full, target=target, full_creds=full_creds))


@app.command()
def report() -> None:
    """View the latest security risk assessment report."""
    print_logo()
    ScanController().view_device_risk()


@app.command()
def results() -> None:
    """Browse raw JSON scan results."""
    print_logo()
    ResultManager().view_results(interactive=True)


@app.command()
def clear() -> None:
    """Delete all saved scan results."""
    print_logo()
    ResultManager().clear_results(interactive=False)


@app.command()
def tui() -> None:
    """Launch the interactive Textual TUI."""
    EdgeWalkerApp().run()


@app.command()
def version() -> None:
    """Display detailed version information."""
    print_logo()

    # Gather system info
    py_ver = sys.version.split()[0]
    os_info = f"{platform.system()} {platform.machine()}"

    # Gather package manager info
    pm_info = "unknown"
    if shutil.which("uv"):
        try:
            # nosec: B607, B603 - uv is a known tool, and we're just getting its version
            uv_ver = subprocess.check_output(["uv", "--version"], text=True).strip().split()[1]
            pm_info = f"uv {uv_ver}"
        except (subprocess.SubprocessError, IndexError, OSError):
            pm_info = "uv"
    elif shutil.which("pip"):
        pm_info = "pip"

    # Display main info
    console.print(f"        [bold {theme.HEADER}]EdgeWalker CLI:[/] {__version__}")
    console.print(f"        [bold {theme.HEADER}]Device ID:[/]      {settings.device_id}")
    console.print(f"        [bold {theme.HEADER}]Python:[/]         {py_ver}")
    console.print(f"        [bold {theme.HEADER}]Package Manager:[/] {pm_info}")
    console.print(f"        [bold {theme.HEADER}]OS:[/]              {os_info}\n")

    console.print(f"        [bold {theme.HEADER}]EdgeWalker:[/] {__version__}")
    console.print("        [dim]... core, modules, tui, cli, utils[/dim]\n")

    # Gather dependency info dynamically
    deps = []
    try:
        requires = importlib.metadata.requires("edgewalker")
        if requires:
            for req in requires:
                # Extract package name (e.g., "rich>=14.3.3" -> "rich")
                dep_name = (
                    req
                    .split(">=")[0]
                    .split("==")[0]
                    .split("~=")[0]
                    .split(">")[0]
                    .split("<")[0]
                    .strip()
                )
                # Handle cases with extras or environment markers
                dep_name = dep_name.split("[")[0].split(";")[0].strip()
                if dep_name:
                    deps.append(dep_name)
    except importlib.metadata.PackageNotFoundError:
        pass

    # Fallback to pyproject.toml if metadata fails (e.g., running from source)
    if not deps:
        try:
            pyproject_path = CONFIG_DIR.parent.parent / "hackathon-q2-2025" / "pyproject.toml"
            # Try relative path from this file too
            if not pyproject_path.exists():
                pyproject_path = Path(__file__).parent.parent.parent.parent / "pyproject.toml"

            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    data = tomllib.load(f)
                    project_deps = data.get("project", {}).get("dependencies", [])
                    for req in project_deps:
                        dep_name = (
                            req
                            .split(">=")[0]
                            .split("==")[0]
                            .split("~=")[0]
                            .split(">")[0]
                            .split("<")[0]
                            .strip()
                        )
                        dep_name = dep_name.split("[")[0].split(";")[0].strip()
                        if dep_name:
                            deps.append(dep_name)
        except (OSError, UnicodeDecodeError):
            pass  # nosec: B110 - fallback to hardcoded list is intentional if parsing fails

    # Final fallback to hardcoded list if all else fails
    if not deps:
        deps = [
            "asyncssh",
            "impacket",
            "loguru",
            "platformdirs",
            "pydantic",
            "pydantic-settings",
            "pyyaml",
            "httpx",
            "rich",
            "semver",
            "textual",
            "typer",
            "validators",
        ]

    console.print("        Package                         Version")
    console.print("        " + "-" * 57)

    for dep in sorted(set(deps)):
        try:
            ver = importlib.metadata.version(dep)
            console.print(f"        {dep:<32} {ver}")
        except importlib.metadata.PackageNotFoundError:
            console.print(f"        {dep:<32} [dim]not installed[/dim]")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: int = typer.Option(
        0,
        "-v",
        "--verbose",
        count=True,
        help="Increase verbosity level (-v for INFO, -vv for DEBUG).",
    ),
    log_file: Optional[str] = typer.Option(
        None, "--log-file", help="Path to write logs to a file."
    ),
    silent: bool = typer.Option(
        False,
        "--silent",
        "-s",
        help="Run in non-interactive mode (bypass prompts).",
    ),
    suppress_warnings: bool = typer.Option(
        False,
        "--suppress-warnings",
        help="Suppress configuration and security warnings in the console.",
    ),
    accept_telemetry: bool = typer.Option(
        False,
        "--accept-telemetry",
        help="Explicitly opt-in to telemetry (used in silent mode).",
    ),
    decline_telemetry: bool = typer.Option(
        False,
        "--decline-telemetry",
        help="Explicitly opt-out of telemetry (used in silent mode).",
    ),
) -> None:
    """EdgeWalker - IoT Home Network Security Scanner."""
    # Update settings with global flags
    if silent:
        update_setting("silent_mode", True)
    if suppress_warnings:
        update_setting("suppress_warnings", True)
    if accept_telemetry:
        update_setting("accept_telemetry", True)
    if decline_telemetry:
        update_setting("decline_telemetry", True)

    # Configure logging using the Typer options
    setup_logging(verbosity=verbose, log_file=log_file)

    if ctx.invoked_subcommand is None:
        # This is handled in main.py to allow TUI by default
        pass


def interactive_mode() -> None:
    """Entry point for the interactive menu interface."""
    controller = ScanController()
    results = ResultManager()
    guided = GuidedScanner(controller)
    menu = InteractiveMenu(controller, results, guided)
    asyncio.run(menu.run())
