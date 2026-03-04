# Standard Library

# Third Party
import pytest
from textual.widgets import Button, Input

# First Party
from edgewalker.tui.app import EdgeWalkerApp
from edgewalker.tui.modals.dialogs import (
    ConfirmModal,
    CredScanTypeModal,
    ScanTypeModal,
    TargetInputModal,
    TelemetryModal,
)


@pytest.mark.asyncio
async def test_telemetry_modal():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        modal = TelemetryModal()

        # Test Yes
        result = None

        def on_dismiss(val):
            nonlocal result
            result = val

        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        btn_yes = modal.query_one("#optin-yes", Button)
        btn_yes.post_message(Button.Pressed(btn_yes))
        await pilot.pause()
        assert result is True

        # Test No
        modal = TelemetryModal()
        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        btn_no = modal.query_one("#optin-no", Button)
        btn_no.post_message(Button.Pressed(btn_no))
        await pilot.pause()
        assert result is False


@pytest.mark.asyncio
async def test_scan_type_modal():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        modal = ScanTypeModal()
        result = None

        def on_dismiss(val):
            nonlocal result
            result = val

        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        btn_full = modal.query_one("#scan-full", Button)
        btn_full.post_message(Button.Pressed(btn_full))
        await pilot.pause()
        assert result is True


@pytest.mark.asyncio
async def test_cred_scan_type_modal():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        modal = CredScanTypeModal()
        result = None

        def on_dismiss(val):
            nonlocal result
            result = val

        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        btn_full = modal.query_one("#cred-full", Button)
        btn_full.post_message(Button.Pressed(btn_full))
        await pilot.pause()
        assert result is True


@pytest.mark.asyncio
async def test_target_input_modal():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        modal = TargetInputModal(default="127.0.0.1")
        result = None

        def on_dismiss(val):
            nonlocal result
            result = val

        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        input_widget = modal.query_one("#target-input", Input)
        input_widget.value = "192.168.1.1"

        # Test Start Scan button
        btn_start = modal.query_one("#target-start", Button)
        btn_start.post_message(Button.Pressed(btn_start))
        await pilot.pause()
        assert result == "192.168.1.1"

        # Test Input Submission (Enter)
        modal = TargetInputModal()
        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        input_widget = modal.query_one("#target-input", Input)
        input_widget.post_message(Input.Submitted(input_widget, "10.0.0.1"))
        await pilot.pause()
        assert result == "10.0.0.1"


@pytest.mark.asyncio
async def test_confirm_modal():
    app = EdgeWalkerApp()
    async with app.run_test() as pilot:
        modal = ConfirmModal("Title", "Message")
        result = None

        def on_dismiss(val):
            nonlocal result
            result = val

        await app.push_screen(modal, on_dismiss)
        await pilot.pause()

        btn_yes = modal.query_one("#confirm-yes", Button)
        btn_yes.post_message(Button.Pressed(btn_yes))
        await pilot.pause()
        assert result is True
