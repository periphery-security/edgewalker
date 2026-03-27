"""mDNS Discovery Module.

Uses zeroconf to discover devices on the local network via mDNS/Bonjour.
"""

from __future__ import annotations

# Standard Library
import asyncio
import socket
from typing import Dict

# Third Party
from loguru import logger
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf


class MDNSListener(ServiceListener):
    """Listener to handle mDNS service discovery events."""

    def __init__(self) -> None:
        """Initialize the listener."""
        self.discovered_devices: Dict[str, str] = {}

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle service update."""
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle service removal."""
        pass

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle new service discovery."""
        if info := zc.get_service_info(type_, name):
            for addr in info.addresses:
                ip = socket.inet_ntoa(addr)
                # Prefer the server name or the service name
                device_name = info.server.split(".")[0] if info.server else name.split(".")[0]
                if ip not in self.discovered_devices:
                    self.discovered_devices[ip] = device_name
                    logger.debug(f"mDNS discovered: {ip} -> {device_name}")


async def discover_mdns(timeout: float = 2.0) -> Dict[str, str]:
    """Perform mDNS discovery for a specified timeout.

    Args:
        timeout: How long to listen for mDNS advertisements.

    Returns:
        Dictionary mapping IP addresses to discovered names.
    """
    logger.info(f"Starting mDNS discovery (timeout={timeout}s)...")
    zeroconf = Zeroconf()
    listener = MDNSListener()

    # Common IoT service types to browse
    services = [
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_printer._tcp.local.",
        "_googlecast._tcp.local.",
        "_hap._tcp.local.",  # HomeKit
        "_spotify-connect._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",  # AirPlay Audio
        "_sonos._tcp.local.",
        "_axis-video._tcp.local.",
        "_smb._tcp.local.",
        "_ftp._tcp.local.",
        "_ssh._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
    ]

    try:
        browser = ServiceBrowser(zeroconf, services, listener)
        await asyncio.sleep(timeout)
        browser.cancel()
    except Exception as e:
        logger.error(f"mDNS discovery failed: {e}")
    finally:
        zeroconf.close()

    return listener.discovered_devices
