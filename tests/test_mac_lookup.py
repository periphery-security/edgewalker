# Standard Library
from unittest.mock import MagicMock, patch

# First Party
from edgewalker.modules.mac_lookup import scanner


def _reset_scanner():
    """Reset scanner module state between tests."""
    scanner._lookup_cache.clear()
    scanner._csv_vendors = None
    scanner._last_request_time = 0.0


def test_normalize_mac():
    """Test MAC normalization."""
    assert scanner.normalize_mac("AA:BB:CC:DD:EE:FF") == "AABBCCDDEEFF"
    assert scanner.normalize_mac("aa.bb.cc.11.22.33") == "AABBCC112233"


def test_get_vendor_unknown():
    """Test vendor lookup for unknown MAC when API returns not found."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp
        assert scanner.get_vendor("00:00:00:00:00:00") == "Unknown"


def test_get_vendor_match():
    """Test vendor lookup for known MAC via API."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "found": True,
        "company": "Test Vendor",
        "address": "123 Test St",
    }

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp
        assert scanner.get_vendor("AA:BB:CC:11:22:33") == "Test Vendor"


def test_get_vendor_api_failure_csv_fallback():
    """Test vendor lookup falls back to CSV when API fails."""
    _reset_scanner()
    vendors_csv = {"AABBCC": "CSV Vendor"}

    with (
        patch("edgewalker.modules.mac_lookup.scanner._lookup_mac_api", return_value=None),
        patch("edgewalker.modules.mac_lookup.scanner._get_csv_vendors", return_value=vendors_csv),
    ):
        assert scanner.get_vendor("AA:BB:CC:11:22:33") == "CSV Vendor"


def test_get_vendor_cached():
    """Test vendor lookup uses in-memory cache."""
    _reset_scanner()
    scanner._lookup_cache["AABBCC112233"] = ("Cached Vendor", "Cached Address")
    assert scanner.get_vendor("AA:BB:CC:11:22:33") == "Cached Vendor"


@patch("httpx.Client")
def test_lookup_mac_api_success(mock_client_cls):
    """Test successful API lookup."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "found": True,
        "company": "API Vendor",
        "address": "456 API Blvd",
    }

    mock_client_cls.return_value.__enter__ = lambda s: s
    mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_client_cls.return_value.get.return_value = mock_resp

    result = scanner._lookup_mac_api("AABBCC112233")
    assert result["found"] is True
    assert result["company"] == "API Vendor"


@patch("httpx.Client")
def test_lookup_mac_api_exception(mock_client_cls):
    """Test API lookup returns None on exception."""
    _reset_scanner()
    mock_client_cls.return_value.__enter__ = lambda s: s
    mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_client_cls.return_value.get.side_effect = Exception("Connection error")

    result = scanner._lookup_mac_api("AABBCC112233")
    assert result is None


@patch("httpx.Client")
def test_lookup_mac_api_rate_limited(mock_client_cls):
    """Test API lookup handles 429 rate limit with retry."""
    _reset_scanner()
    rate_resp = MagicMock()
    rate_resp.status_code = 429
    rate_resp.headers = {"Retry-After": "0.01"}

    ok_resp = MagicMock()
    ok_resp.status_code = 200
    ok_resp.json.return_value = {"success": True, "found": True, "company": "Retry Vendor"}

    mock_client_cls.return_value.__enter__ = lambda s: s
    mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_client_cls.return_value.get.side_effect = [rate_resp, ok_resp]

    result = scanner._lookup_mac_api("AABBCC112233")
    assert result["company"] == "Retry Vendor"


@patch("httpx.Client")
def test_lookup_mac_api_500(mock_client_cls):
    """Test API lookup returns None on server error."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 500

    mock_client_cls.return_value.__enter__ = lambda s: s
    mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_client_cls.return_value.get.return_value = mock_resp

    result = scanner._lookup_mac_api("AABBCC112233")
    assert result is None


def test_load_vendors_from_csv(tmp_path):
    """Test loading vendors from CSV file."""
    csv_file = tmp_path / "vendors.csv"
    csv_file.write_text("prefix,vendor\nAABBCC,CSV Vendor\n")
    with patch("edgewalker.modules.mac_lookup.scanner.VENDOR_DB", csv_file):
        scanner._csv_vendors = None
        res = scanner._load_vendors_from_csv()
        assert res["AABBCC"] == "CSV Vendor"


def test_load_vendors_from_csv_no_file(tmp_path):
    """Test loading vendors from non-existent CSV."""
    with patch("edgewalker.modules.mac_lookup.scanner.VENDOR_DB", tmp_path / "nonexistent.csv"):
        assert scanner._load_vendors_from_csv() == {}


def test_lookup_mac():
    """Test lookup_mac model return."""
    _reset_scanner()
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

        res = scanner.lookup_mac("AA:BB:CC:11:22:33")
        assert res.found is True
        assert res.organization == "Test Vendor"
        assert res.address == "Test Address"


def test_lookup_mac_not_found():
    """Test lookup_mac when vendor not found."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__ = lambda s: s
        mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value.get.return_value = mock_resp

        res = scanner.lookup_mac("00:00:00:00:00:00")
        assert res.found is False
        assert res.organization is None


def test_lookup_mac_cached():
    """Test lookup_mac uses in-memory cache."""
    _reset_scanner()
    scanner._lookup_cache["AABBCC112233"] = ("Cached Vendor", "Cached Addr")

    res = scanner.lookup_mac("AA:BB:CC:11:22:33")
    assert res.found is True
    assert res.organization == "Cached Vendor"
    assert res.address == "Cached Addr"


def test_get_vendor_short_mac():
    """Test get_vendor with too short MAC."""
    _reset_scanner()
    assert scanner.get_vendor("AA:BB") == "Unknown"


def test_lookup_mac_short_mac():
    """Test lookup_mac with too short MAC."""
    _reset_scanner()
    res = scanner.lookup_mac("AA:BB")
    assert res.found is False


def test_csv_fallback_vendor():
    """Test CSV fallback with different prefix lengths."""
    _reset_scanner()
    vendors = {
        "AABBCCDDE": "Long Vendor",
        "AABBCCD": "Mid Vendor",
        "AABBCC": "Short Vendor",
    }
    with patch("edgewalker.modules.mac_lookup.scanner._get_csv_vendors", return_value=vendors):
        assert scanner._csv_fallback_vendor("AABBCCDDEEFF") == "Long Vendor"
        assert scanner._csv_fallback_vendor("AABBCCDDEE00") == "Long Vendor"
        assert scanner._csv_fallback_vendor("AABBCCDD0000") == "Mid Vendor"
        assert scanner._csv_fallback_vendor("AABBCC000000") == "Short Vendor"
        assert scanner._csv_fallback_vendor("FFFFFF000000") == "Unknown"
        assert scanner._csv_fallback_vendor("AABB") == "Unknown"


@patch("edgewalker.modules.mac_lookup.scanner.settings")
def test_rate_limit_delay_no_key(mock_settings):
    """Test rate limit delay without API key."""
    mock_settings.mac_api_key = None
    assert scanner._rate_limit_delay() == 0.5


@patch("edgewalker.modules.mac_lookup.scanner.settings")
def test_rate_limit_delay_with_key(mock_settings):
    """Test rate limit delay with API key."""
    mock_settings.mac_api_key = "test-key"
    assert scanner._rate_limit_delay() == 1.0 / 50


@patch("httpx.Client")
def test_lookup_mac_api_passes_api_key(mock_client_cls):
    """Test that API key is passed as query parameter."""
    _reset_scanner()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "found": False}

    mock_client_cls.return_value.__enter__ = lambda s: s
    mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_client_cls.return_value.get.return_value = mock_resp

    with patch("edgewalker.modules.mac_lookup.scanner.settings") as mock_settings:
        mock_settings.mac_api_key = "my-api-key"
        mock_settings.api_timeout = 10
        scanner._lookup_mac_api("AABBCC112233")

        call_kwargs = mock_client_cls.return_value.get.call_args[1]
        assert call_kwargs["params"]["apiKey"] == "my-api-key"


def test_init_cache(tmp_path):
    """Test init_cache sets cache directory."""
    scanner.init_cache(tmp_path)
    assert scanner._cache_dir == tmp_path
    assert scanner._default_lookup.cache_dir == tmp_path
