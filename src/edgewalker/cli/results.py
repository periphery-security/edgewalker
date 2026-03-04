"""Result Manager — Handles viewing and clearing scan results."""

# Standard Library
import json
from datetime import datetime

# Third Party
from loguru import logger
from rich import box
from rich.panel import Panel
from rich.table import Table

# First Party
from edgewalker import theme, utils
from edgewalker.core.config import settings


class ResultManager:
    """Handles viewing and clearing scan results."""

    def check_previous_results(self) -> None:
        """Check for existing results and prompt to clear them."""
        if utils.has_any_results():
            utils.console.print()
            utils.console.print(
                f"  [{theme.WARNING}]{theme.ICON_WARN} "
                f"Previous scan results detected.[/{theme.WARNING}]"
            )
            choice = utils.get_input("Clear previous results before starting? [y/N]", "n")
            if choice.lower() == "y":
                self.clear_results(interactive=False)
                utils.console.print(f"  [{theme.SUCCESS}]Results cleared.[/{theme.SUCCESS}]")
            utils.console.print()

    def clear_results(self, interactive: bool = True) -> None:
        """Delete all saved scan results."""
        if not settings.output_dir.exists():
            return

        files = list(settings.output_dir.glob("*.json"))
        if not files:
            if interactive:
                logger.info("No results to clear.")
            return

        if interactive:
            utils.console.print()
            logger.warning(f"This will delete {len(files)} result files.")
            confirm = utils.get_input("Are you sure? [y/N]", "n")
            if confirm.lower() != "y":
                logger.info("Cancelled.")
                return

        for f in files:
            try:
                f.unlink()
            except Exception as e:
                logger.error(f"Failed to delete {f.name}: {e}")

        if interactive:
            logger.success("All results cleared.")

    def view_results(self, interactive: bool = True) -> None:
        """Browse and view raw JSON results."""
        if not utils.has_any_results():
            if not interactive:
                logger.info("No scan results found.")
            return

        if not settings.output_dir.exists():
            logger.error("No results directory found.")
            return

        files = sorted(
            list(settings.output_dir.glob("*.json")),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )

        if not files:
            logger.info("No scan results found.")
            return

        if not interactive:
            self._print_results_table(files)
            return

        while True:
            utils.clear_screen()
            utils.print_logo()

            self._print_results_table(files)

            utils.console.print()
            choice = utils.get_input("Select file # to view (0 to back)", "0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(files):
                    self._view_file(files[idx])
                    utils.get_input("Press Enter to continue", "")
                else:
                    logger.error("Invalid selection.")
                    utils.get_input("Press Enter to continue", "")
            except ValueError:
                logger.error("Please enter a number.")
                utils.get_input("Press Enter to continue", "")

    def _print_results_table(self, files: list) -> None:
        """Print a table of available result files."""
        table = Table(box=box.SIMPLE, header_style=f"bold {theme.HEADER}")
        table.add_column("#", style=theme.MUTED_STYLE, width=3)
        table.add_column("File", style=theme.PRIMARY)
        table.add_column("Size", justify="right")
        table.add_column("Modified", style=theme.MUTED_STYLE)

        for i, f in enumerate(files):
            size = f.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"

            mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            table.add_row(str(i + 1), f.name, size_str, mtime)

        utils.console.print(
            Panel(
                table,
                title=f"[{theme.HEADER}]SAVED SCAN RESULTS[/{theme.HEADER}]",
                border_style=theme.ACCENT,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    def _view_file(self, path: object) -> None:
        """Print raw JSON content of a file."""
        utils.clear_screen()
        utils.print_header(f"VIEWING: {path.name}")
        utils.console.print()

        try:
            with open(path) as f:
                data = json.load(f)
            utils.console.print_json(data=data)
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
