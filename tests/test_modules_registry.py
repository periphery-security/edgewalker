# Standard Library
from unittest.mock import patch

# Third Party
import pytest

# First Party
from edgewalker.modules import ScanModule, _discover_modules, get_modules


@pytest.mark.asyncio
async def test_scan_module_base():
    class TestModule(ScanModule):
        slug = "test"

    assert TestModule in get_modules()

    with pytest.raises(NotImplementedError):
        await TestModule().scan()


def test_discover_modules_error():
    with patch("pkgutil.iter_modules") as mock_iter:
        mock_iter.return_value = [(None, "edgewalker.modules.broken", True)]
        with patch("importlib.import_module", side_effect=Exception("Fail")):
            _discover_modules()
            # Should log warning but not crash
