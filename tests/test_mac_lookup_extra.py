# Standard Library
from unittest.mock import MagicMock, patch

# First Party
from edgewalker.modules.mac_lookup.scanner import MacLookup, _lookup_cache, _lookup_mac_api


def _reset():
    """Reset module state."""
    _lookup_cache.clear()


def test_mac_lookup_normalize():
    """Test MacLookup normalize_mac method."""
    ml = MacLookup()
    assert ml.normalize_mac("00:11:22:33:44:55") == "001122334455"
    assert ml.normalize_mac("00-11-22-33-44-55") == "001122334455"
    assert ml.normalize_mac("0011.2233.4455") == "001122334455"


def test_mac_lookup_get_vendor():
    """Test MacLookup get_vendor with API mock."""
    _reset()
    ml = MacLookup()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "found": True,
        "company": "Test Vendor",
    }

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp
        assert ml.get_vendor("00:11:22:33:44:55") == "Test Vendor"


def test_mac_lookup_get_vendor_unknown():
    """Test MacLookup get_vendor when not found and no CSV match."""
    _reset()
    ml = MacLookup()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp
        assert ml.get_vendor("AA:BB:CC:DD:EE:FF") == "Unknown"


def test_mac_lookup_lookup():
    """Test MacLookup lookup method."""
    _reset()
    ml = MacLookup()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "found": True,
        "company": "Test Vendor",
        "address": "Test Address",
    }

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp
        res = ml.lookup("00:11:22:33:44:55")
        assert res.found is True
        assert res.organization == "Test Vendor"
        assert res.address == "Test Address"


def test_mac_lookup_api_with_key():
    """Test that API key is included in request params."""
    _reset()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    with (
        patch("httpx.Client") as mock_client_cls,
        patch("edgewalker.modules.mac_lookup.scanner.settings") as mock_settings,
    ):
        mock_settings.mac_api_key = "test-key-123"
        mock_settings.api_timeout = 10

        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp

        _lookup_mac_api("001122334455")
        call_kwargs = mock_client_cls.return_value.get.call_args[1]
        assert call_kwargs["params"]["apiKey"] == "test-key-123"


def test_mac_lookup_api_without_key():
    """Test that no apiKey param is sent when key is not configured."""
    _reset()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    with (
        patch("httpx.Client") as mock_client_cls,
        patch("edgewalker.modules.mac_lookup.scanner.settings") as mock_settings,
    ):
        mock_settings.mac_api_key = None
        mock_settings.api_timeout = 10

        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp

        _lookup_mac_api("001122334455")
        call_kwargs = mock_client_cls.return_value.get.call_args[1]
        assert "apiKey" not in call_kwargs["params"]
