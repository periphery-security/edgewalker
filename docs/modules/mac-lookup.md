# MAC Lookup Module

**Location:** `edgewalker/modules/mac_lookup/`

Resolves MAC addresses to device manufacturer names using the IEEE OUI (Organizationally Unique Identifier) database.

## How It Works

MAC addresses contain a vendor prefix — the first 3 bytes (6 hex characters) identify the manufacturer. Some vendors use longer prefixes (7 or 9 characters) for more specific identification.

The module checks prefixes from longest to shortest for the most specific match.

## Data Source

EdgeWalker fetches vendor data from the `maclookup.app` API:

1. **API lookup** — queries the `maclookup.app` API for individual MAC addresses.
2. **In-memory caching** — caches results in memory during a scan to avoid duplicate API calls.
3. **Local fallback** — if the API remains unreachable, falls back to a local `vendors.csv` file bundled with the application.

### Configuration

| Variable | Default | Description |
|---|---|---|
| `EW_MAC_API_URL` | `https://api.maclookup.app/v2/macs` | MACLookup API base URL |
| `EW_MAC_API_KEY` | `None` | MACLookup API key (increases rate limit) |

### Security Validation

EdgeWalker enforces security best practices for the MAC lookup API:
- **HTTPS Enforcement:** The `EW_MAC_API_URL` must use `https://` unless pointing to `localhost`.
- **Domain Verification:** EdgeWalker warns you if the API endpoint points to a non-standard domain, as this endpoint receives your MAC addresses and API key.

## Public API

```python
from edgewalker.modules.mac_lookup import get_vendor, normalize_mac

# Look up a vendor
vendor = get_vendor("AA:BB:CC:DD:EE:FF")  # Returns "TP-Link" or "Unknown"

# Normalize a MAC address
normalized = normalize_mac("aa:bb:cc:dd:ee:ff")  # Returns "AABBCCDDEEFF"
```

## Requirements

- Internet access for API lookups (falls back to local CSV if offline)
- No root/sudo required
