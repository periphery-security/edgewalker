# Standard Library
from unittest.mock import patch

# Third Party
import pytest
from textual.screen import Screen

# First Party
from edgewalker.tui.app import EdgeWalkerApp
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
    assert "[1] Test" in str(item.render())


@pytest.mark.asyncio
async def test_nav_item_active_toggle():
    item = NavItem("o", "Overview", view="overview")
    assert item.view == "overview"
    assert item.active is False

    item.set_active(True)
    assert item.active is True
    assert item.has_class("-active")

    item.set_active(False)
    assert item.active is False
    assert not item.has_class("-active")


@pytest.mark.asyncio
async def test_telemetry_status():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        status = TelemetryStatus()
        screen = Screen()
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
            screen = Screen()
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


@pytest.mark.asyncio
async def test_navigation_panel_groups_and_active_view():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        panel = NavigationPanel()
        screen = Screen()
        await app.push_screen(screen)
        await screen.mount(panel)
        await pilot.pause()

        # SCAN group mnemonics and VIEW group mnemonics are present.
        items = {item.key: item for item in panel.query(NavItem)}
        assert set(items) == {"s", "S", "r", "o", "d", "f", "l"}

        # View items carry their ContentSwitcher name; scan items do not.
        assert items["o"].view == "overview"
        assert items["d"].view == "devices"
        assert items["s"].view is None

        # Overview is the default active view on mount.
        assert items["o"].active is True
        assert items["d"].active is False

        panel.set_active_view("devices")
        assert items["d"].active is True
        assert items["o"].active is False
