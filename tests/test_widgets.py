# Third Party
import pytest
from textual.app import App, ComposeResult

# First Party
from edgewalker.tui.widgets import NavItem, NavPanel, NavSeparator, StatusBadge


class MockApp(App):
    def compose(self) -> ComposeResult:
        yield NavPanel()
        yield NavItem("1", "Test")
        yield StatusBadge("Test")
        yield NavSeparator()


@pytest.mark.asyncio
async def test_nav_panel():
    app = MockApp()
    async with app.run_test() as pilot:
        panel = app.query_one(NavPanel)
        assert panel is not None
        assert panel.query_one("#status-port") is not None


@pytest.mark.asyncio
async def test_nav_item():
    app = MockApp()
    async with app.run_test() as pilot:
        item = app.query_one(NavItem)
        assert "[1] Test" in str(item.render())


@pytest.mark.asyncio
async def test_status_badge():
    app = MockApp()
    async with app.run_test() as pilot:
        badge = app.query_one(StatusBadge)
        badge.set_status(True, "detail")
        assert "Test" in str(badge.render())
        assert "detail" in str(badge.render())
