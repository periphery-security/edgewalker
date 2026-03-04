# Data & Privacy

EdgeWalker is designed to be transparent about what it does with your data.

## What Stays Local

All scan results are saved locally to the application's configuration directory (e.g., `~/Library/Application Support/edgewalker/scans/` on macOS) as JSON files. They never leave your machine unless you explicitly opt in to anonymous data sharing.

The credential database (`data/creds.csv`) is bundled with the tool. No network calls are made to load credentials — you can inspect every username/password pair that will be tested by opening the CSV.

## Anonymous Data Sharing (Opt-In)

On first run, EdgeWalker asks whether you'd like to share anonymised scan results with Periphery's research team. This is entirely optional.

### What Is Shared (if you opt in)

- Open ports and service versions found
- Whether default credentials were vulnerable (not the actual passwords)
- CVE matches for discovered software

### What Is Never Shared

- Your IP address — the last 2 octets are removed before transmission (`192.168.1.50` becomes `192.168.x.x`)
- Your MAC addresses — only the vendor prefix is kept (`aa:bb:cc:dd:ee:ff` becomes `aa:bb:cc:xx:xx:xx`)
- Hostnames — removed entirely
- Actual passwords — only the fact that a default credential worked is recorded

### How Anonymisation Works

Before any data leaves your machine, `telemetry.py` processes it:

1. **IP anonymisation**: The last two octets are replaced with `x.x`, making it impossible to identify your specific network
2. **MAC anonymisation**: Only the first 3 bytes (vendor OUI prefix) are kept — enough to identify the device manufacturer but not the specific device
3. **Hostname stripping**: All hostname fields are removed from the payload

### Why We Collect This

This data helps us understand IoT vulnerabilities at scale:

- Which default credentials are most common in the wild
- Which device types are most frequently exposed
- Emerging vulnerability trends across consumer IoT

The findings feed back into improving EdgeWalker's credential database and informing Periphery's security research.

### How to Opt Out

- **During first run**: Select "No thanks" when prompted
- **After opting in**: You can opt out via the TUI settings menu or by deleting the configuration file:
  ```bash
  # On macOS:
  rm "~/Library/Application Support/edgewalker/config.yaml"
  # On Linux:
  rm ~/.config/edgewalker/config.yaml
  ```

### Server-Side Security

The data collection API is hardened:

- Rate-limited (10 submissions per minute per IP)
- Request size capped at 5MB
- Input validated and sanitised (JSON depth limits, suspicious content detection)
- Stored on disk only — no database, no third-party analytics
- AppArmor confined with restricted filesystem and network access
- No logging of client IP addresses in stored data (only a one-way hash for deduplication)
