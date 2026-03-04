# Third Party
import pytest
from textual.app import App, ComposeResult

# First Party
from edgewalker.tui.modals import ScanTypeModal, TargetInputModal, TelemetryModal


class MockApp(App):
    def compose(self) -> ComposeResult:
        yield from []


@pytest.mark.asyncio
async def test_telemetry_enabled_modal():
    app = MockApp()
    async with app.run_test() as pilot:
        modal = TelemetryModal()
        await app.push_screen(modal)
        await pilot.pause()
        assert app.screen == modal

        # Test accept
        await pilot.press("y")
        await pilot.pause()
        # Modal should be dismissed


@pytest.mark.asyncio
async def test_scan_type_modal():
    app = MockApp()
    async with app.run_test() as pilot:
        modal = ScanTypeModal()
        await app.push_screen(modal)
        await pilot.pause()

        # Click quick scan
        await pilot.click("#scan-quick")
        await pilot.pause()


@pytest.mark.asyncio
async def test_target_input_modal():
    app = MockApp()
    async with app.run_test() as pilot:
        modal = TargetInputModal(default="192.168.1.0/24")
        await app.push_screen(modal)
        await pilot.pause()

        # Test input submission
        await pilot.press("enter")
        await pilot.pause()
