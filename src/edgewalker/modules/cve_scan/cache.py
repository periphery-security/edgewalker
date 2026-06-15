"""Local cache for NVD CVE lookups.

NVD queries are slow (rate-limited to one request every few seconds) and return
identical data for the same product/version between scans. This module provides a
small disk-backed cache with a TTL so repeated and scheduled scans avoid
re-hitting the API -- and keep working when NVD is unreachable, serving the last
known result instead of failing.

The cache is opt-in: it is inert until ``init_cache()`` wires it to a directory
(done from ``main.py``). Code paths that never initialise it -- such as unit
tests calling ``search_cves_async`` directly -- behave exactly as before.
"""

from __future__ import annotations

# Standard Library
import json
import os
import time
from pathlib import Path

# Third Party
from loguru import logger

# First Party
from edgewalker.core.config import settings


class CveCache:
    """Disk-backed, TTL-bounded cache of NVD lookups keyed by product/version."""

    def __init__(self, cache_dir: Path, ttl: int | None = None) -> None:
        """Initialise the cache.

        Args:
            cache_dir: Directory the cache file lives in.
            ttl: Seconds an entry stays fresh. Defaults to ``settings.nvd_cache_ttl``.
        """
        self.path = Path(cache_dir) / "cve_cache.json"
        self._ttl = ttl
        self._entries: dict[str, dict] = {}
        self._load()

    @property
    def ttl(self) -> int:
        """Time-to-live in seconds (read from settings if not pinned at init)."""
        return self._ttl if self._ttl is not None else settings.nvd_cache_ttl

    @staticmethod
    def _key(product: str, version: str | None) -> str:
        """Build a normalised cache key from a product and version."""
        return f"{(product or '').lower().strip()}:{(version or '').lower().strip()}"

    def _load(self) -> None:
        """Load the cache file into memory, tolerating a missing/corrupt file."""
        if not self.path.exists():
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._entries = data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read CVE cache at {self.path}: {e}")
            self._entries = {}

    def get(self, product: str, version: str | None = None) -> list | None:
        """Return cached CVEs for a product/version, or None if absent/expired."""
        entry = self._entries.get(self._key(product, version))
        if not entry:
            return None
        age = time.time() - entry.get("fetched_at", 0)
        if age > self.ttl:
            logger.debug(f"CVE cache expired for {product} {version} (age {int(age)}s)")
            return None
        logger.debug(f"CVE cache hit for {product} {version}")
        return entry.get("cves", [])

    def set(self, product: str, version: str | None, cves: list) -> None:
        """Store CVEs for a product/version and persist the cache to disk."""
        self._entries[self._key(product, version)] = {
            "cves": cves,
            "fetched_at": time.time(),
        }
        self._persist()

    def _persist(self) -> None:
        """Write the in-memory cache to disk with restricted permissions."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self._entries, f)
        except OSError as e:
            logger.warning(f"Could not write CVE cache at {self.path}: {e}")


# Module-level cache instance -- set by init_cache() from main.py. Stays None
# (caching disabled) until then, so direct/test callers are unaffected.
_cache: CveCache | None = None


def init_cache(cache_dir: Path) -> None:
    """Enable the CVE cache, backing it with a file in ``cache_dir``."""
    global _cache
    _cache = CveCache(cache_dir)


def get_cache() -> CveCache | None:
    """Return the active cache instance, or None if caching is disabled."""
    return _cache
