# Standard Library
import runpy
from unittest.mock import patch


def test_main_module_execution():
    with patch("edgewalker.main.main") as mock_main:
        # Use runpy to execute the module as __main__
        runpy.run_module("edgewalker", run_name="__main__")
        assert mock_main.called
