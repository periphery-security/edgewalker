"""Tests for the `?` help overlay (tui/modals/help.py)."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest
from rich.console import Console

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.modals.help import HelpModal
from edgewalker.tui.screens.dashboard import DashboardScreen


def _keymap_text(modal: HelpModal) -> str:
    """Render the modal's grouped keymap to plain text."""
    console = Console(width=80, record=True, file=None)
    console.print(modal._build_keymap())
    return console.export_text()


def _sections():
    return [
        ("SCAN", [("s", "Quick scan"), ("r", "Re-run all")]),
        ("VIEW", [("o", "Overview"), ("d", "Devices")]),
    ]


@pytest.mark.asyncio
async def test_help_modal_renders_keymap():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await app.push_screen(HelpModal(_sections()))
            await pilot.pause()

            text = _keymap_text(app.screen)
            assert "SCAN" in text
            assert "Quick scan" in text
            assert "Devices" in text


@pytest.mark.asyncio
async def test_help_modal_closes_on_escape():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            await app.push_screen(HelpModal(_sections()))
            await pilot.pause()
            assert isinstance(app.screen, HelpModal)

            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, HelpModal)


@pytest.mark.asyncio
async def test_dashboard_help_action_opens_modal():
    app = EdgeWalkerApp()
    with (
        patch("textual.widgets.Header", return_value=MagicMock()),
        patch("edgewalker.tui.app.check_nmap_permissions", return_value=True),
    ):
        async with app.run_test() as pilot:
            screen = DashboardScreen()
            await app.push_screen(screen)
            await pilot.pause()

            screen.action_help()
            await pilot.pause()
            assert isinstance(app.screen, HelpModal)

            # The dashboard keymap covers the scan + view mnemonics.
            text = _keymap_text(app.screen)
            assert "Findings" in text
            assert "Live log" in text
