# Port Scan Module

**Location:** `edgewalker/modules/port_scan/`

Wraps `nmap` to discover devices and open ports on a network. Supports two scan modes with automatic parallelisation.

## Quick Scan (~30 seconds)

Scans 28 common edge device ports per host:

| Port | Service | Why |
|---|---|---|
| 21 | FTP | File transfer, often unencrypted |
| 22 | SSH | Remote access |
| 23, 2323 | Telnet | Unencrypted remote access (Mirai target) |
| 80, 81, 443, 8080, 8081, 8443 | HTTP/HTTPS | Web interfaces |
| 554 | RTSP | Camera video streams |
| 1883, 8883 | MQTT | device messaging protocol |
| 502 | Modbus | Industrial/EV charger protocol |
| 5900 | VNC | Remote desktop |
| 37777, 34567 | Camera | Dahua / Chinese DVR ports |
| 1900, 5000, 5353 | Discovery | UPnP, mDNS |
| 445 | SMB | NAS file sharing |
| 9100 | Printer | Raw printing |
| 7547 | TR-069 | ISP management (often exploited) |
| 8123, 32400 | Smart home | Home Assistant, Plex |
| 53 | DNS | Name resolution |
| 161 | SNMP | Network management |
| 6667 | IRC | Botnet indicator |

Steps:
1. Ping sweep to discover live hosts
2. Parallel port scan of edge ports per host
3. Service version detection on open ports

## Full Scan (~15 minutes+)

Checks all 65,535 ports per host in three phases:

1. **Ping sweep** — find live hosts
2. **SYN discovery** — fast scan across all ports (no version probes)
3. **Service detection** — version and OS detection only on ports found open

## Parallelisation

EdgeWalker splits hosts into batches across multiple `nmap` processes. Configure this via `EW_SCAN_WORKERS` (default: 4).

## Public API

```python
from edgewalker.modules.port_scan import scan, quick_scan, full_scan

# Run a quick scan
results = quick_scan("192.168.1.0/24", verbose=True)

# Run a full scan
results = full_scan("192.168.1.0/24", verbose=True)

# Auto-detect target and scan
from edgewalker.modules.port_scan import get_default_target

target = get_default_target()
```

## Output Format

```json
{
  "success": true,
  "scan_type": "quick",
  "target": "192.168.1.0/24",
  "is_demo": false,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "TP-Link",
      "os_matches": ["Linux 4.x"],
      "tcp_ports": [
        {
          "port": 80,
          "state": "open",
          "service": "http",
          "product": "lighttpd",
          "version": "1.4.59"
        }
      ]
    }
  ]
}
```

## Security & Permissions

- **File Permissions:** EdgeWalker saves scan results with `0o600` permissions (read/write for owner only).
- **Directory Permissions:** EdgeWalker creates the output directory with `0o700` permissions.
- **Demo Mode:** When setting `EW_DEMO_MODE=1`, EdgeWalker saves results to a separate `demo_scans` directory and sets the `is_demo` field to `true`.

## Requirements

- `nmap` must exist on the system PATH
- SYN scanning requires root/sudo privileges
