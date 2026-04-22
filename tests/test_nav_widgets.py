# Standard Library
from unittest.mock import patch

# Third Party
import pytest

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.screens.home import HomeScreen
from edgewalker.tui.widgets.navigation import NavigationPanel, NavItem, StatusBadge, TelemetryStatus


@pytest.mark.asyncio
async def test_status_badge():
    badge = StatusBadge("Test")
    assert "Test" in badge.render()

    badge.set_status(True, "ok")
    assert "Test" in badge.render()
    assert "ok" in badge.render()

    badge.set_status(True, "vulnerable")
    assert "Test" in badge.render()
    assert "vulnerable" in badge.render()


@pytest.mark.asyncio
async def test_nav_item():
    item = NavItem("1", "Test")
    assert "[1] Test" in item.render()


@pytest.mark.asyncio
async def test_telemetry_status():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        status = TelemetryStatus()
        screen = HomeScreen()
        await app.push_screen(screen)
        await screen.mount(status)
        await pilot.pause()

        app.telemetry_status = "running"
        await pilot.pause()
        assert "Running" in status.render().plain

        app.telemetry_status = "disabled"
        await pilot.pause()
        assert "Disabled" in status.render().plain


@pytest.mark.asyncio
async def test_navigation_panel_update():
    app = EdgeWalkerApp()
    with patch(
        "edgewalker.tui.widgets.navigation.get_scan_status",
        return_value={
            "port_scan": True,
            "port_scan_type": "quick",
            "password_scan": True,
            "vulnerable_devices": 1,
            "cve_scan": True,
            "cves_found": 5,
            "sql_scan": False,
            "web_scan": False,
            "sql_vulns": 0,
            "web_vulns": 0,
        },
    ):
        async with app.run_test() as pilot:
            panel = NavigationPanel()
            screen = HomeScreen()
            await app.push_screen(screen)
            await screen.mount(panel)
            await pilot.pause()

            port_badge = panel.query_one("#status-port", StatusBadge)
            assert port_badge.active is True
            assert port_badge.detail == "quick"

            pwd_badge = panel.query_one("#status-pwd", StatusBadge)
            assert pwd_badge.active is True
            assert pwd_badge.detail == "vulnerable"

            cve_badge = panel.query_one("#status-cve", StatusBadge)
            assert cve_badge.active is True
            assert cve_badge.detail == "5c"
