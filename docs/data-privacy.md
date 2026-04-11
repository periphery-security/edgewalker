# Data & Privacy

EdgeWalker maintains transparency regarding your data.

## Local Data Security

EdgeWalker saves all scan results locally to the application's configuration directory (e.g., `~/Library/Application Support/edgewalker/scans/` on macOS) as JSON files. These files never leave your machine unless you explicitly opt in to anonymous data sharing.

To protect your sensitive scan data, EdgeWalker enforces strict file and directory permissions:
- **Directories:** EdgeWalker creates the configuration and scan output directories with `0o700` permissions (read, write, and execute for the owner only).
- **Files:** EdgeWalker saves configuration and scan result files with `0o600` permissions (read and write for the owner only).

The tool bundles the credential database (`data/creds.csv`). No network calls occur when loading credentials — you can inspect every username/password pair within the CSV.

## API Endpoint Security

EdgeWalker communicates with several external APIs for CVE lookups, MAC address identification, and telemetry. To ensure your data remains secure during transmission:

- **HTTPS Enforcement:** EdgeWalker requires all API endpoints to use HTTPS. It refuses connections to insecure HTTP endpoints unless they point to `localhost`.
- **Domain Verification:** EdgeWalker validates that API endpoints point to trusted domains (e.g., `services.nvd.nist.gov`, `api.maclookup.app`, `api.periphery.security`). If it detects a non-standard domain, EdgeWalker issues a prominent warning, as these endpoints may receive sensitive information like your API keys.

## Anonymous Data Sharing (Opt-Out)

EdgeWalker collects anonymized usage data by default to help us improve the tool and identify emerging edge device vulnerabilities. This data is vital for our research and helps us maintain the most up-to-date default credential database.

### What EdgeWalker Shares

- Open ports and service versions found
- Whether default credentials worked (not the actual passwords)
- CVE matches for discovered software
- SQL and Web service audit summaries

### Inspect the Data Structures

We believe in full transparency. You can inspect the exact JSON schemas and example data for the data we collect in our repository:

- **Port Scan**: [Schema](../telemetry_samples/port_scan_schema.json) | [Example](../telemetry_samples/port_scan_example.json)
- **Password Scan**: [Schema](../telemetry_samples/password_scan_schema.json) | [Example](../telemetry_samples/password_scan_example.json)
- **CVE Scan**: [Schema](../telemetry_samples/cve_scan_schema.json) | [Example](../telemetry_samples/cve_scan_example.json)
- **SQL Scan**: [Schema](../telemetry_samples/sql_scan_schema.json) | [Example](../telemetry_samples/sql_scan_example.json)
- **Web Scan**: [Schema](../telemetry_samples/web_scan_schema.json) | [Example](../telemetry_samples/web_scan_example.json)

### What EdgeWalker Never Shares

- Your IP address — EdgeWalker removes the last 2 octets before transmission (`192.168.1.50` becomes `192.168.0.0`)
- Your MAC addresses — EdgeWalker only keeps the vendor prefix (`aa:bb:cc:dd:ee:ff` becomes `aa:bb:cc:00:00:00`). This allows us to identify the device manufacturer (e.g., "TP-Link" or "Philips Hue") without identifying your specific device.
- Hostnames — EdgeWalker removes these entirely
- Actual passwords — EdgeWalker only records the fact that a default credential worked

### How Anonymisation Works

Before any data leaves your machine, `telemetry.py` processes it:

1. **IP anonymisation**: EdgeWalker replaces the last two octets with `0.0`, preventing identification of your specific network.
2. **MAC anonymisation**: EdgeWalker only keeps the first 3 bytes (vendor OUI prefix) — enough to identify the device manufacturer but not the specific device.
3. **Hostname stripping**: EdgeWalker removes all hostname fields from the payload.
4. **Device Correlation**: To allow our research team to correlate data across different scan types (e.g., tying a password scan result to a port scan result for the same device) without using PII, we generate a `device_correlation_id`. This is a truncated SHA-256 hash of the device's IP or MAC address, keyed with your persistent `session_id`. This ID is unique to your session and cannot be reversed to find the original IP or MAC address.

### Why We Collect This

This data helps us understand edge device vulnerabilities at scale:

- Which default credentials appear most commonly in the wild
- Which device types suffer exposure most frequently
- Emerging vulnerability trends across consumer edge devices

The findings feed back into improving EdgeWalker's credential database and informing Periphery's security research.

|In addition we attempt to work with the device vendors to assist them in improving their security posture which in turn means you, the end user, get a more secure experience.

### How to Opt Out

You can opt out of telemetry at any time:

- **Via CLI**: Run `edgewalker config set telemetry_enabled false`
- **Via Environment Variable**: Set `EW_TELEMETRY_ENABLED=0`
- **Via TUI**: Disable "Enable Telemetry" in the Settings menu.

### Non-Interactive (Silent) Mode Telemetry

When running EdgeWalker in automated environments (CI/CD) using the `--silent` flag, telemetry is enabled by default unless explicitly declined using the `--decline-telemetry` flag or the `EW_TELEMETRY_ENABLED=0` environment variable.

### Server-Side Security

The data collection API features hardening:

- Rate-limiting (10 submissions per minute per IP)
- Request size capped at 5MB
- Input validation and sanitisation (JSON depth limits, suspicious content detection)
- Disk-only storage — no database, no third-party analytics
- AppArmor confinement with restricted filesystem and network access
- No logging of client IP addresses in stored data (only a one-way hash for deduplication)
