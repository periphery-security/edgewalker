"""Port Scan Module.

Wraps nmap to discover hosts and open ports on a network.
- Quick scan: Ping sweep + common IoT ports (parallel batches)
- Full scan: Ping sweep + all 65535 ports on live hosts (parallel batches)
"""

# First Party
from edgewalker.modules.port_scan.scanner import (
    check_privileges,
    full_scan,
    get_default_target,
    get_local_ip,
    get_nmap_command,
    ping_sweep,
    quick_scan,
    scan,
    validate_target,
)

__all__ = [
    "check_privileges",
    "full_scan",
    "get_default_target",
    "get_local_ip",
    "get_nmap_command",
    "ping_sweep",
    "quick_scan",
    "scan",
    "validate_target",
]
