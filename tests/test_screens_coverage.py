# Standard Library
import os

# Third Party
import pytest
from textual.app import App, ComposeResult
from textual.widgets import Static

# First Party
from edgewalker.tui.screens.base import BaseScreen


class MockApp(App):
    def on_mount(self) -> None:
        self.push_screen(TestScreen())


class TestScreen(BaseScreen):
    def compose_content(self) -> ComposeResult:
        yield Static("Content", id="test-content")


@pytest.mark.asyncio
async def test_base_screen_compose_demo_mode():
    """Test BaseScreen compose in demo mode."""
    with patch.dict(os.environ, {"EW_DEMO_MODE": "1"}):
        app = MockApp()
        async with app.run_test() as pilot:
            screen = app.screen
            header = screen.query_one("#header-title", Static)
            # In Textual, we can check the renderable via _renderable or just check if it's mounted
            assert header is not None
            assert "DEMO MODE" in str(header.render())


@pytest.mark.asyncio
async def test_base_screen_update_footer():
    """Test BaseScreen update_footer."""
    app = MockApp()
    async with app.run_test() as pilot:
        screen = app.screen
        screen.update_footer("New Footer")
        footer = screen.query_one("#app-footer", Static)
        assert "New Footer" in str(footer.render())


def test_base_screen_default_compose_content():
    """Test default compose_content yields empty list."""
    screen = BaseScreen()
    assert list(screen.compose_content()) == []


# Standard Library
from unittest.mock import patch
