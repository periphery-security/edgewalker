# Password Scan Module

**Location:** `edgewalker/modules/password_scan/`

Tests default and weak credentials against SSH, FTP, Telnet, and SMB services found during the port scan.

## Credential Database

EdgeWalker stores credentials locally in `edgewalker/data/creds.csv` — a plain CSV file you can inspect, edit, or extend. No network calls occur when loading credentials.

The database contains ~430 entries sourced from known IoT default credentials:

| Service | Entries | Examples |
|---|---|---|
| SSH | ~170 | `root:alpine`, `pi:raspberry`, `admin:admin` |
| FTP | ~70 | `anonymous:`, `admin:admin`, `root:root` |
| Telnet | ~160 | `root:xc3511`, `admin:admin`, `888888:888888` |
| SMB | ~24 | `admin:admin`, `guest:`, `Administrator:password` |

### CSV Format

```csv
service,user,password
ssh,root,alpine
ssh,admin,admin
ftp,anonymous,
telnet,root,root
```

### Adding Custom Credentials

Add rows to `data/creds.csv` following the same format. The module reads the entire file on first use and caches it in memory.

## How Testing Works

### Protocol Support

- **SSH**: Tested via `asyncssh` (Python async SSH library). Suppresses noisy transport-layer logging.
- **FTP**: Tested via Python's built-in `ftplib`.
- **Telnet**: Tested via raw sockets. Uses pattern matching for login/password prompts and success/failure indicators. Compatible with Python 3.13+ (doesn't rely on the removed `telnetlib`).
- **SMB**: Tested via `impacket` (SMB/CIFS library). Targets port 445 — covers NAS devices, Windows file shares, and printers.

### Concurrency

Testing occurs concurrently at two levels:

1. **Across hosts** — up to 8 hosts tested in parallel (configure this via `EW_CRED_WORKERS`)
2. **Within each host** — SSH, FTP, Telnet, and SMB tests run simultaneously

### Early Exit

Scanning stops at the first successful login per service. If `admin:admin` works on SSH, EdgeWalker ceases testing further credentials for that service.

### Top-N Mode

By default, EdgeWalker tests only the top 10 credentials per service for speed. Use `--top 50` or select "all" in interactive mode for more thorough testing.

## Public API

```python
from edgewalker.modules.password_scan import scan, load_credentials

# Load credentials for a service
ssh_creds = load_credentials("ssh")           # all
ssh_top10 = load_credentials("ssh", top_n=10) # top 10

# Scan hosts from port scan results
results = scan(hosts=port_scan_hosts, top_n=10, verbose=True)
```

## Output Format

```json
{
  "is_demo": false,
  "results": [
    {
      "ip": "192.168.1.50",
      "port": 22,
      "service": "ssh",
      "login_attempt": "successful",
      "tested_count": 10,
      "credentials": {
        "user": "pi",
        "password": "raspberry"
      }
    },
    {
      "ip": "192.168.1.50",
      "port": 21,
      "service": "ftp",
      "login_attempt": "failed",
      "tested_count": 10,
      "credentials": null
    }
  ],
  "summary": {
    "total_hosts": 3,
    "vulnerable_hosts": 1,
    "services_tested": 6,
    "credentials_found": 1
  }
}
```

## Security & Permissions

- **File Permissions:** EdgeWalker saves scan results with `0o600` permissions (read/write for owner only).
- **Directory Permissions:** EdgeWalker creates the output directory with `0o700` permissions.
- **Demo Mode:** When setting `EW_DEMO_MODE=1`, EdgeWalker saves results to a separate `demo_scans` directory and sets the `is_demo` field to `true`.

## Requirements

- `asyncssh` (installed via pip as a dependency)
- `impacket` (installed via pip as a dependency — used for SMB testing)
- No root/sudo required — credential testing uses standard TCP connections
