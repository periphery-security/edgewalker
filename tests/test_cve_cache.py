# Standard Library
import sqlite3
import time
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.cve_scan import cache as cache_mod, scanner
from edgewalker.modules.cve_scan.cache import CveCache


@pytest.fixture
def db_path(tmp_path):
    """A temp SQLite database path for the CVE cache."""
    return tmp_path / "edgewalker.db"


@pytest.fixture(autouse=True)
def reset_module_cache():
    """Keep the module-level cache disabled unless a test opts in."""
    cache_mod._cache = None
    yield
    cache_mod._cache = None


def test_set_then_get_returns_cached(db_path):
    c = CveCache(db_path)
    cves = [{"id": "CVE-2023-1", "severity": "HIGH", "score": 7.5}]
    c.set("openssh", "8.9", cves)
    assert c.get("openssh", "8.9") == cves


def test_key_is_normalised(db_path):
    c = CveCache(db_path)
    c.set("OpenSSH", "8.9", [{"id": "CVE-X"}])
    assert c.get("  openssh ", "8.9") == [{"id": "CVE-X"}]


def test_get_miss_returns_none(db_path):
    assert CveCache(db_path).get("nginx", "1.0") is None


def test_expired_entry_returns_none(db_path):
    c = CveCache(db_path, ttl=100)
    c.set("apache", "2.4", [{"id": "CVE-Y"}])
    with patch("edgewalker.modules.cve_scan.cache.time.time", return_value=time.time() + 1000):
        assert c.get("apache", "2.4") is None


def test_persists_across_instances(db_path):
    CveCache(db_path).set("nginx", "1.0", [{"id": "CVE-Z"}])
    # A fresh instance against the same DB reads what the first wrote.
    assert CveCache(db_path).get("nginx", "1.0") == [{"id": "CVE-Z"}]


def test_creates_table_in_shared_db(db_path):
    CveCache(db_path)
    with sqlite3.connect(db_path) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "cve_cache" in names


def test_ttl_falls_back_to_settings(db_path):
    with patch("edgewalker.modules.cve_scan.cache.settings") as mock_settings:
        mock_settings.nvd_cache_ttl = 42
        assert CveCache(db_path).ttl == 42


def test_init_cache_enables_module_cache(db_path):
    assert cache_mod.get_cache() is None
    cache_mod.init_cache(db_path)
    assert isinstance(cache_mod.get_cache(), CveCache)


@pytest.mark.asyncio
async def test_search_cves_async_uses_cache_on_hit(db_path):
    """A warm cache short-circuits the NVD call entirely."""
    cache_mod.init_cache(db_path)
    cache_mod.get_cache().set("product", "1.0", [{"id": "CVE-CACHED"}])

    client = AsyncMock()
    res = await scanner.search_cves_async(client, "product", "1.0")

    assert res == [{"id": "CVE-CACHED"}]
    client.get.assert_not_called()


@pytest.mark.asyncio
async def test_search_cves_async_populates_cache_on_miss(db_path):
    """A cache miss hits NVD once, then the result is served from cache."""
    cache_mod.init_cache(db_path)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-FETCHED",
                    "descriptions": [{"lang": "en", "value": "desc"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }
    client = AsyncMock()
    client.get.return_value = mock_response

    first = await scanner.search_cves_async(client, "product", "1.0")
    assert first[0]["id"] == "CVE-FETCHED"
    assert client.get.call_count == 1

    # Second call is served from the cache without another request.
    second = await scanner.search_cves_async(client, "product", "1.0")
    assert second == first
    assert client.get.call_count == 1

    # And it was actually written to the cve_cache table.
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_failed_lookup_is_not_cached(db_path):
    """Non-200 responses must not poison the cache."""
    cache_mod.init_cache(db_path)

    bad_response = MagicMock()
    bad_response.status_code = 500
    client = AsyncMock()
    client.get.return_value = bad_response

    assert await scanner.search_cves_async(client, "product", "1.0") == []
    assert cache_mod.get_cache().get("product", "1.0") is None
