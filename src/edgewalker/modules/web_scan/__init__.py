"""Web Scan Module."""

# First Party
from edgewalker.modules.web_scan.models import WebScanModel, WebScanResultModel
from edgewalker.modules.web_scan.scanner import WebScanner

__all__ = ["WebScanner", "WebScanModel", "WebScanResultModel"]
