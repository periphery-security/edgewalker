# Standard Library
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.modules.cve_scan import cache as cache_mod, scanner
from edgewalker.modules.cve_scan.cache import CveCache


@pytest.fixture
def cache_dir(tmp_path):
    """A temp cache directory."""
    return tmp_path / "cache"


@pytest.fixture(autouse=True)
def reset_module_cache():
    """Keep the module-level cache disabled unless a test opts in."""
    cache_mod._cache = None
    yield
    cache_mod._cache = None


def test_set_then_get_returns_cached(cache_dir):
    c = CveCache(cache_dir)
    cves = [{"id": "CVE-2023-1", "severity": "HIGH", "score": 7.5}]
    c.set("openssh", "8.9", cves)
    assert c.get("openssh", "8.9") == cves


def test_key_is_normalised(cache_dir):
    c = CveCache(cache_dir)
    c.set("OpenSSH", "8.9", [{"id": "CVE-X"}])
    assert c.get("  openssh ", "8.9") == [{"id": "CVE-X"}]


def test_get_miss_returns_none(cache_dir):
    c = CveCache(cache_dir)
    assert c.get("nginx", "1.0") is None


def test_expired_entry_returns_none(cache_dir):
    c = CveCache(cache_dir, ttl=100)
    c.set("apache", "2.4", [{"id": "CVE-Y"}])
    # Force the entry to look old.
    with patch("edgewalker.modules.cve_scan.cache.time.time", return_value=time.time() + 1000):
        assert c.get("apache", "2.4") is None


def test_persists_across_instances(cache_dir):
    CveCache(cache_dir).set("nginx", "1.0", [{"id": "CVE-Z"}])
    # A fresh instance reads the file written by the first.
    assert CveCache(cache_dir).get("nginx", "1.0") == [{"id": "CVE-Z"}]


def test_corrupt_cache_file_is_tolerated(cache_dir):
    cache_dir.mkdir(parents=True)
    (cache_dir / "cve_cache.json").write_text("{not valid json")
    c = CveCache(cache_dir)
    assert c.get("anything", "1.0") is None


def test_file_written_with_restricted_permissions(cache_dir):
    c = CveCache(cache_dir)
    c.set("svc", "1.0", [{"id": "CVE-1"}])
    assert (c.path.stat().st_mode & 0o777) == 0o600


def test_ttl_falls_back_to_settings(cache_dir):
    with patch("edgewalker.modules.cve_scan.cache.settings") as mock_settings:
        mock_settings.nvd_cache_ttl = 42
        c = CveCache(cache_dir)
        assert c.ttl == 42


def test_init_cache_enables_module_cache(cache_dir):
    assert cache_mod.get_cache() is None
    cache_mod.init_cache(cache_dir)
    assert isinstance(cache_mod.get_cache(), CveCache)


@pytest.mark.asyncio
async def test_search_cves_async_uses_cache_on_hit(cache_dir):
    """A warm cache short-circuits the NVD call entirely."""
    cache_mod.init_cache(cache_dir)
    cache_mod.get_cache().set("product", "1.0", [{"id": "CVE-CACHED"}])

    client = AsyncMock()
    res = await scanner.search_cves_async(client, "product", "1.0")

    assert res == [{"id": "CVE-CACHED"}]
    client.get.assert_not_called()


@pytest.mark.asyncio
async def test_search_cves_async_populates_cache_on_miss(cache_dir):
    """A cache miss hits NVD once, then the result is served from cache."""
    cache_mod.init_cache(cache_dir)

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

    # And it was actually written to disk.
    stored = json.loads((cache_dir / "cve_cache.json").read_text())
    assert "product:1.0" in stored


@pytest.mark.asyncio
async def test_failed_lookup_is_not_cached(cache_dir):
    """Non-200 responses must not poison the cache."""
    cache_mod.init_cache(cache_dir)

    bad_response = MagicMock()
    bad_response.status_code = 500
    client = AsyncMock()
    client.get.return_value = bad_response

    assert await scanner.search_cves_async(client, "product", "1.0") == []
    assert cache_mod.get_cache().get("product", "1.0") is None
