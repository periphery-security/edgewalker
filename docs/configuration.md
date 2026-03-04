# Configuration

All settings can be overridden via environment variables prefixed with `EW_`. Defaults are defined in `edgewalker/config.py`.

## Environment Variables

### API

| Variable | Default | Description |
|---|---|---|
| `EW_API_URL` | `https://api.periphery.security/edgewalker/v1` | EdgeWalker API endpoint |
| `EW_API_TIMEOUT` | `10` | API request timeout (seconds) |
| `EW_MAC_API_KEY` | `None` | MACLookup API key (increases rate limit) |

### Scan Timeouts

| Variable | Default | Description |
|---|---|---|
| `EW_NMAP_TIMEOUT` | `900` (15 min) | Quick scan timeout |
| `EW_NMAP_FULL_TIMEOUT` | `7200` (2 hr) | Full scan timeout |
| `EW_PING_SWEEP_TIMEOUT` | `300` (5 min) | Host discovery timeout |
| `EW_CONN_TIMEOUT` | `5` | TCP connection timeout for credential tests |
| `EW_NVD_RATE_DELAY` | `6` | Delay between NVD API requests (rate limit) |

### Concurrency

| Variable | Default | Description |
|---|---|---|
| `EW_CRED_WORKERS` | `8` | Max concurrent threads for credential testing |
| `EW_SCAN_WORKERS` | `4` | Max parallel nmap processes |

### NVD

| Variable | Default | Description |
|---|---|---|
| `EW_NVD_API_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE search endpoint |
| `EW_NVD_API_KEY` | `None` | NVD API key (increases rate limit) |

### UI & System

| Variable | Default | Description |
|---|---|---|
| `EW_THEME` | `periphery` | Active UI theme slug |
| `EW_IOT_PORTS` | `[21, 22, ...]` | Common IoT ports for quick scan |
| `EW_TELEMETRY_ENABLED` | `None` | User opt-in status for anonymous data sharing |
| `EW_CONFIG_DIR` | `~/.config/edgewalker` | Configuration directory override |
| `EW_CACHE_DIR` | `~/.cache/edgewalker` | Cache directory override |

## Examples

```bash
# Faster scans with more workers
EW_SCAN_WORKERS=8 EW_NMAP_TIMEOUT=300 sudo edgewalker scan

# Increase credential test concurrency
EW_CRED_WORKERS=16 edgewalker creds

# Use a custom NVD endpoint
EW_NVD_API_URL=https://my-proxy.example.com/nvd edgewalker cve
```

## File Paths

| Path | Purpose |
|---|---|
| `CACHE_DIR/` | Cached vendor data (e.g., `~/Library/Caches/edgewalker/` on macOS) |
| `CONFIG_DIR/` | Configuration and session data (e.g., `~/Library/Application Support/edgewalker/` on macOS) |
| `CONFIG_DIR/scans/` | Scan output files |
