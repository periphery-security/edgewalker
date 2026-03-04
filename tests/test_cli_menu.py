# Standard Library
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.cli.controller import ScanController
from edgewalker.cli.guided import GuidedScanner
from edgewalker.cli.menu import InteractiveMenu
from edgewalker.cli.results import ResultManager


@pytest.mark.asyncio
async def test_menu_run_exit():
    controller = MagicMock(spec=ScanController)
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    with patch("edgewalker.utils.get_input", return_value="0"):
        with patch(
            "edgewalker.core.telemetry.TelemetryManager.has_seen_telemetry_prompt",
            return_value=True,
        ):
            await menu.run()
            # Should exit immediately after one loop iteration


@pytest.mark.asyncio
async def test_menu_settings():
    controller = MagicMock(spec=ScanController)
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    # Choice 1: Toggle telemetry, Choice 0: Back
    with patch("edgewalker.utils.get_input", side_effect=["1", "0"]):
        with patch("edgewalker.cli.menu.update_setting") as mock_update:
            with patch("edgewalker.utils.press_enter"):
                menu._settings_menu()
                assert mock_update.called


@pytest.mark.asyncio
async def test_menu_telemetry_prompt():
    controller = MagicMock(spec=ScanController)
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    with patch("edgewalker.utils.ensure_telemetry_choice") as mock_ensure:
        with patch("edgewalker.utils.get_input", return_value="0"):
            await menu.run()
            mock_ensure.assert_called_once()


@pytest.mark.asyncio
async def test_menu_manual_mode_exit():
    controller = MagicMock(spec=ScanController)
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    with patch("edgewalker.utils.get_input", return_value="0"):
        await menu._manual_mode()


@pytest.mark.asyncio
async def test_menu_manual_mode_scans():
    controller = MagicMock(spec=ScanController)
    controller.run_port_scan = AsyncMock()
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)
    guided_scanner.prompt_next_scan = AsyncMock()

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    # Choice 2: Quick Scan, Choice 0: Exit
    with patch("edgewalker.utils.get_input", side_effect=["2", "0"]):
        with patch("edgewalker.cli.guided.GuidedScanner.prompt_next_scan", new_callable=AsyncMock):
            await menu._manual_mode()
            assert controller.run_port_scan.called


@pytest.mark.asyncio
async def test_menu_warn_port_scan():
    controller = MagicMock(spec=ScanController)
    result_manager = MagicMock(spec=ResultManager)
    guided_scanner = MagicMock(spec=GuidedScanner)

    menu = InteractiveMenu(controller, result_manager, guided_scanner)

    with patch("edgewalker.utils.press_enter"):
        menu._warn_port_scan_required("test")
