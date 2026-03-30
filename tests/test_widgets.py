# Standard Library
from typing import Any

# Third Party
import pytest
from textual.app import App, ComposeResult

# First Party
from edgewalker.tui.widgets import NavItem, NavPanel, NavSeparator, StatusBadge, TopologyWidget


class MockApp(App):
    def __init__(self, scan_results: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.scan_results = scan_results or {}

    def compose(self) -> ComposeResult:
        yield NavPanel()
        yield NavItem("1", "Test")
        yield StatusBadge("Test")
        yield NavSeparator()
        yield TopologyWidget(self.scan_results)


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


@pytest.mark.asyncio
async def test_topology_widget():
    scan_results = {
        "gateway_ip": "192.168.1.1",
        "hosts": [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway",
                "vendor": "Cisco",
                "risk": {"score": 10},
            },
            {
                "ip": "192.168.1.10",
                "hostname": "device1",
                "vendor": "Apple",
                "risk": {"score": 50},
            },
        ],
    }
    app = MockApp(scan_results)
    async with app.run_test() as pilot:
        widget = app.query_one(TopologyWidget)
        assert widget is not None
        assert widget.root.label.plain == " ⌕ Internet (Cloud)"
        assert len(widget.root.children) == 1
        gw_node = widget.root.children[0]
        assert "Gateway: gateway" in gw_node.label.plain
        assert len(gw_node.children) == 2  # Scanner + device1
