"""MAC Address Vendor Lookup Module.

Looks up MAC addresses against the MACLookup API (maclookup.app) to identify
device manufacturers. Falls back to local CSV if the API is unreachable.
"""

from __future__ import annotations

# Standard Library
import csv
import re
import time
from pathlib import Path

# Third Party
import httpx
from loguru import logger

# First Party
from edgewalker.core.config import settings
from edgewalker.core.models import MacSearchResult

# Path to local vendor database (offline fallback)
VENDOR_DB = Path(__file__).parent / "data" / "vendors.csv"

# Cache directory -- set by init_cache() from main.py
_cache_dir: Path | None = None

# In-memory cache for API results: normalized_mac -> (company, address)
_lookup_cache: dict[str, tuple[str, str | None]] = {}

# Rate limiting state
_last_request_time: float = 0.0


def _rate_limit_delay() -> float:
    """Return the minimum delay between API requests in seconds."""
    if settings.mac_api_key:
        return 1.0 / 50  # 50 req/s with API key
    return 1.0 / 2  # 2 req/s without API key


def _wait_for_rate_limit() -> None:
    """Sleep if needed to respect API rate limits."""
    global _last_request_time
    now = time.monotonic()
    elapsed = now - _last_request_time
    delay = _rate_limit_delay()
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _last_request_time = time.monotonic()


def _lookup_mac_api(mac: str) -> dict | None:
    """Look up a MAC address via the MACLookup API.

    Args:
        mac: Normalized MAC address (uppercase, no separators).

    Returns:
        API response dict or None on failure.
    """
    _wait_for_rate_limit()

    params: dict[str, str] = {}
    if settings.mac_api_key:
        params["apiKey"] = settings.mac_api_key

    try:
        logger.debug(f"Looking up MAC: {mac} via API")
        with httpx.Client() as client:
            resp = client.get(
                f"{settings.mac_api_url}/{mac}",
                params=params,
                timeout=settings.api_timeout,
            )
        logger.debug(f"MAC API Response: {resp.status_code}")
    except Exception as e:
        logger.error(f"MAC API request failed for {mac}: {e}")
        return None

    if resp.status_code == 429:
        # Rate limited - respect Retry-After header
        retry_after = float(resp.headers.get("Retry-After", "1"))
        logger.warning(f"MAC API Rate limit hit (429). Retrying after {retry_after}s...")
        time.sleep(retry_after)
        try:
            with httpx.Client() as client:
                resp = client.get(
                    f"{settings.mac_api_url}/{mac}",
                    params=params,
                    timeout=settings.api_timeout,
                )
            logger.debug(f"MAC API Retry Response: {resp.status_code}")
        except Exception as e:
            logger.error(f"MAC API retry failed for {mac}: {e}")
            return None

    if resp.status_code == 200:
        return resp.json()

    logger.error(f"MAC API error: {resp.status_code} - {resp.text[:200]}")
    return None


# Lazy-loaded CSV fallback
_csv_vendors: dict | None = None


def _load_vendors_from_csv() -> dict:
    """Load vendor database from local CSV file."""
    vendors: dict[str, str] = {}
    if not VENDOR_DB.exists():
        return vendors
    with open(VENDOR_DB, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = row.get("prefix", "").upper()
            vendor = row.get("vendor", "")
            if prefix:
                vendors[prefix] = vendor
    return vendors


def _get_csv_vendors() -> dict:
    """Get CSV vendors, loading on first use."""
    global _csv_vendors
    if _csv_vendors is None:
        _csv_vendors = _load_vendors_from_csv()
    return _csv_vendors


def _csv_fallback_vendor(normalized: str) -> str:
    """Look up vendor from local CSV fallback."""
    logger.debug(f"Falling back to local CSV for MAC: {normalized}")
    vendors = _get_csv_vendors()

    if len(normalized) < 6:
        return "Unknown"

    for length in [9, 7, 6]:
        if len(normalized) >= length:
            prefix = normalized[:length]
            if prefix in vendors:
                return vendors[prefix]

    return "Unknown"


class MacLookup:
    """MAC Address Vendor Lookup class."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialize the MacLookup class.

        Args:
            cache_dir: Optional directory to cache vendor data.
        """
        self.cache_dir = cache_dir

    def normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to uppercase without separators."""
        return re.sub(r"[.:\-]", "", mac).upper()

    def get_vendor(self, mac: str) -> str:
        """Get vendor name for a MAC address."""
        normalized = self.normalize_mac(mac)

        if len(normalized) < 6:
            return "Unknown"

        # Check in-memory cache
        if normalized in _lookup_cache:
            return _lookup_cache[normalized][0]

        # Try API lookup
        result = _lookup_mac_api(normalized)
        if result is not None:
            if result.get("found"):
                company = result.get("company", "Unknown") or "Unknown"
                address = result.get("address")
                _lookup_cache[normalized] = (company, address)
                return company
            else:
                _lookup_cache[normalized] = ("Unknown", None)
                return "Unknown"

        # API failed, fall back to CSV
        return _csv_fallback_vendor(normalized)

    def lookup(self, mac: str) -> MacSearchResult:
        """Look up a MAC address and return a MacSearchResult model."""
        normalized = self.normalize_mac(mac)

        if len(normalized) < 6:
            return MacSearchResult(
                mac_address=mac,
                normalized_mac=normalized,
                found=False,
            )

        # Check in-memory cache
        if normalized in _lookup_cache:
            company, address = _lookup_cache[normalized]
            found = company != "Unknown"
            return MacSearchResult(
                mac_address=mac,
                normalized_mac=normalized,
                found=found,
                organization=company if found else None,
                address=address,
            )

        # Try API lookup
        result = _lookup_mac_api(normalized)
        if result is not None:
            if result.get("found"):
                company = result.get("company", "Unknown") or "Unknown"
                address = result.get("address")
                _lookup_cache[normalized] = (company, address)
                return MacSearchResult(
                    mac_address=mac,
                    normalized_mac=normalized,
                    found=True,
                    organization=company,
                    address=address,
                )
            else:
                _lookup_cache[normalized] = ("Unknown", None)
                return MacSearchResult(
                    mac_address=mac,
                    normalized_mac=normalized,
                    found=False,
                )

        # API failed, fall back to CSV
        vendor = _csv_fallback_vendor(normalized)
        found = vendor != "Unknown"
        return MacSearchResult(
            mac_address=mac,
            normalized_mac=normalized,
            found=found,
            organization=vendor if found else None,
        )


# Global instance for backward compatibility
_default_lookup = MacLookup()


def init_cache(cache_dir: Path) -> None:
    """Set the cache directory."""
    global _cache_dir
    _cache_dir = cache_dir
    _default_lookup.cache_dir = cache_dir


def normalize_mac(mac: str) -> str:
    """Backward compatible normalize_mac."""
    return _default_lookup.normalize_mac(mac)


def get_vendor(mac: str) -> str:
    """Backward compatible get_vendor."""
    return _default_lookup.get_vendor(mac)


def lookup_mac(mac: str) -> MacSearchResult:
    """Backward compatible lookup_mac."""
    return _default_lookup.lookup(mac)
