"""Local cache for NVD CVE lookups, backed by the scan-history database.

NVD queries are slow (rate-limited to one request every few seconds) and return
identical data for the same product/version between scans. This cache stores
results in the ``cve_cache`` table of the shared SQLite database with a TTL, so
repeated and scheduled scans avoid re-hitting the API -- and keep working when
NVD is unreachable, serving the last known result instead of failing.

The cache is opt-in: it is inert until ``init_cache()`` wires it to a database
path (done from ``main.py``). Code paths that never initialise it -- such as
unit tests calling ``search_cves_async`` directly -- behave exactly as before.
"""

from __future__ import annotations

# Standard Library
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

# Third Party
from loguru import logger

# First Party
from edgewalker.core.config import settings


class CveCache:
    """TTL-bounded cache of NVD lookups in the ``cve_cache`` table."""

    def __init__(self, db_path: Path | str, ttl: int | None = None) -> None:
        """Open the cache against ``db_path``; ensure the ``cve_cache`` table exists.

        Args:
            db_path: Path to the shared SQLite database.
            ttl: Seconds an entry stays fresh. Defaults to ``settings.nvd_cache_ttl``.
        """
        self.db_path = Path(db_path)
        self._ttl = ttl
        self._ensure_table()

    @property
    def ttl(self) -> int:
        """Time-to-live in seconds (read from settings if not pinned at init)."""
        return self._ttl if self._ttl is not None else settings.nvd_cache_ttl

    @staticmethod
    def _key(product: str, version: str | None) -> str:
        """Build a normalised cache key from a product and version."""
        return f"{(product or '').lower().strip()}:{(version or '').lower().strip()}"

    def _ensure_table(self) -> None:
        """Create the cve_cache table if absent (mirrors the sqlite_store schema)."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cve_cache "
                "(cache_key TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at REAL NOT NULL)"
            )

    def get(self, product: str, version: str | None = None) -> list | None:
        """Return cached CVEs for a product/version, or None if absent/expired."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT data, fetched_at FROM cve_cache WHERE cache_key = ?",
                (self._key(product, version),),
            ).fetchone()
        if row is None:
            return None
        data, fetched_at = row
        if time.time() - fetched_at > self.ttl:
            logger.debug(f"CVE cache expired for {product} {version}")
            return None
        logger.debug(f"CVE cache hit for {product} {version}")
        return json.loads(data)

    def set(self, product: str, version: str | None, cves: list) -> None:
        """Store CVEs for a product/version in the cache."""
        with closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (cache_key, data, fetched_at) VALUES (?, ?, ?)",
                (self._key(product, version), json.dumps(cves), time.time()),
            )


# Module-level cache instance -- set by init_cache() from main.py. Stays None
# (caching disabled) until then, so direct/test callers are unaffected.
_cache: CveCache | None = None


def init_cache(db_path: Path) -> None:
    """Enable the CVE cache, backing it with the ``cve_cache`` table at ``db_path``."""
    global _cache
    _cache = CveCache(db_path)


def get_cache() -> CveCache | None:
    """Return the active cache instance, or None if caching is disabled."""
    return _cache
