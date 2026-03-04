"""CVE Scan Module.

Checks software versions discovered during the port scan against the NVD.
"""

# First Party
from edgewalker.modules.cve_scan.scanner import scan, search_cves

__all__ = ["scan", "search_cves"]
