# Configuration

Environment variables prefixed with `EW_` override all settings. `edgewalker/config.py` defines the default values.

## Environment Variables

### API

| Variable | Default | Description |
|---|---|---|
| `EW_API_URL` | `https://api.periphery.security/edgewalker/v1` | EdgeWalker API endpoint |
| `EW_API_TIMEOUT` | `10` | API request timeout (seconds) |
| `EW_MAC_API_URL` | `https://api.maclookup.app/v2/macs` | MACLookup API base URL |
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
| `EW_IOT_PORTS` | `[21, 22, ...]` | Common edge ports for quick scan |
| `EW_TELEMETRY_ENABLED` | `None` | User opt-in status for anonymous data sharing |
| `EW_SILENT_MODE` | `False` | Run in non-interactive mode (bypass prompts) |
| `EW_SUPPRESS_WARNINGS` | `False` | Suppress configuration and security warnings in the console |
| `EW_CONFIG_DIR` | `~/.config/edgewalker` | Configuration directory override |
| `EW_CACHE_DIR` | `~/.cache/edgewalker` | Cache directory override |
| `EW_DEMO_MODE` | `0` | Set to `1` to enable demo mode with mock data |

## Non-Interactive (Silent) Mode

For CI/CD pipelines and automated environments, EdgeWalker provides a non-interactive mode that bypasses all user prompts.

### Global Flags

These flags can be used with any command:

- `--silent` or `-s`: Enables non-interactive mode.
- `--suppress-warnings`: Hides configuration override panels and security warnings from the console.
- `--accept-telemetry`: Explicitly opts-in to anonymous telemetry (required in silent mode if no preference is set).
- `--decline-telemetry`: Explicitly opts-out of anonymous telemetry (required in silent mode if no preference is set).
- `--colorblind`: Use colorblind-safe palette (Okabe-Ito) and save to config.

### CI/CD Usage

When running in a fresh environment (like a GitHub Action), you must provide a telemetry choice if you use `--silent`. If no choice is provided, the CLI will exit with an error to ensure an explicit decision is made.

```bash
# Run a scan in CI/CD without any prompts
edgewalker --silent --suppress-warnings --accept-telemetry scan --target 192.168.1.0/24
```

## Security Validation

EdgeWalker enforces security best practices for its configuration:

- **HTTPS Enforcement:** All API URLs (`EW_API_URL`, `EW_NVD_API_URL`, `EW_MAC_API_URL`) must use `https://` unless pointing to `localhost` or `127.0.0.1`.
- **Domain Verification:** EdgeWalker warns you if API endpoints point to non-standard domains, as these endpoints receive sensitive information like your API keys.
- **File Permissions:** EdgeWalker saves configuration files with restricted permissions (`0o600`) and creates configuration directories with `0o700` to ensure only the owner can read or modify them.

## CLI Configuration Management

Manage your configuration directly from the CLI:

```bash
# Show current configuration and active overrides
edgewalker config show

# Update a setting
edgewalker config set theme dracula

# Print the path to the config file
edgewalker config path
```

### Handling Overrides

When environment variables or a `.env` file override your `config.yaml` settings, EdgeWalker displays a warning. To proceed with a scan while overrides remain active without a confirmation prompt, use the `--allow-override` flag:

```bash
EW_SCAN_WORKERS=8 edgewalker scan --allow-override
```

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
| `CONFIG_DIR/scans/` | Scan output files (standard mode) |
| `CONFIG_DIR/demo_scans/` | Scan output files (demo mode) |
