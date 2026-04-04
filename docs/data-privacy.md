# Data & Privacy

EdgeWalker maintains transparency regarding your data.

## Local Data Security

EdgeWalker saves all scan results locally to the application's configuration directory (e.g., `~/Library/Application Support/edgewalker/scans/` on macOS) as JSON files. These files never leave your machine unless you explicitly opt in to anonymous data sharing.

To protect your sensitive scan data, EdgeWalker enforces strict file and directory permissions:
- **Directories:** EdgeWalker creates the configuration and scan output directories with `0o700` permissions (read, write, and execute for the owner only).
- **Files:** EdgeWalker saves configuration and scan result files with `0o600` permissions (read and write for the owner only).

The tool bundles the credential database (`data/creds.csv`). No network calls occur when loading credentials — you can inspect every username/password pair within the CSV.

## API Endpoint Security

EdgeWalker communicates with several external APIs for CVE lookups, MAC address identification, and (if opted-in) telemetry. To ensure your data remains secure during transmission:

- **HTTPS Enforcement:** EdgeWalker requires all API endpoints to use HTTPS. It refuses connections to insecure HTTP endpoints unless they point to `localhost`.
- **Domain Verification:** EdgeWalker validates that API endpoints point to trusted domains (e.g., `services.nvd.nist.gov`, `api.maclookup.app`, `api.periphery.security`). If it detects a non-standard domain, EdgeWalker issues a prominent warning, as these endpoints may receive sensitive information like your API keys.

## Anonymous Data Sharing (Opt-In)

On first run, EdgeWalker asks whether you wish to share anonymised scan results with Periphery's research team. This remains entirely optional.

### What EdgeWalker Shares (if you opt in)

- Open ports and service versions found
- Whether default credentials worked (not the actual passwords)
- CVE matches for discovered software

### What EdgeWalker Never Shares

- Your IP address — EdgeWalker removes the last 2 octets before transmission (`192.168.1.50` becomes `192.168.0.0`)
- Your MAC addresses — EdgeWalker only keeps the vendor prefix (`aa:bb:cc:dd:ee:ff` becomes `aa:bb:cc:00:00:00`)
- Hostnames — EdgeWalker removes these entirely
- Actual passwords — EdgeWalker only records the fact that a default credential worked

### How Anonymisation Works

Before any data leaves your machine, `telemetry.py` processes it:

1. **IP anonymisation**: EdgeWalker replaces the last two octets with `0.0`, preventing identification of your specific network.
2. **MAC anonymisation**: EdgeWalker only keeps the first 3 bytes (vendor OUI prefix) — enough to identify the device manufacturer but not the specific device.
3. **Hostname stripping**: EdgeWalker removes all hostname fields from the payload.

### Why We Collect This

This data helps us understand edge device vulnerabilities at scale:

- Which default credentials appear most commonly in the wild
- Which device types suffer exposure most frequently
- Emerging vulnerability trends across consumer edge devices

The findings feed back into improving EdgeWalker's credential database and informing Periphery's security research.

### How to Opt Out

- **During first run**: Select "No thanks" when prompted.
- **In Silent Mode**: Use the `--decline-telemetry` flag.
- **After opting in**: Opt out via the TUI settings menu or by deleting the configuration file:
  ```bash
  # On macOS:
  rm "~/Library/Application Support/edgewalker/config.yaml"
  # On Linux:
  rm ~/.config/edgewalker/config.yaml
  ```

### Non-Interactive (Silent) Mode Telemetry

When running EdgeWalker in automated environments (CI/CD) using the `--silent` flag, the tool requires an explicit telemetry choice if one has not been previously set. This ensures that data sharing is never enabled by default without a conscious decision.

- Use `--accept-telemetry` to opt-in.
- Use `--decline-telemetry` to opt-out.

If neither flag is provided in silent mode on a fresh installation, EdgeWalker will exit with an error.

### Server-Side Security

The data collection API features hardening:

- Rate-limiting (10 submissions per minute per IP)
- Request size capped at 5MB
- Input validation and sanitisation (JSON depth limits, suspicious content detection)
- Disk-only storage — no database, no third-party analytics
- AppArmor confinement with restricted filesystem and network access
- No logging of client IP addresses in stored data (only a one-way hash for deduplication)
