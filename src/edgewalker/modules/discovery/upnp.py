"""UPnP Discovery Module.

Uses SSDP to discover devices and fetches their description XML.
"""

from __future__ import annotations

# Standard Library
import asyncio
import socket
import xml.etree.ElementTree as ET  # nosec: B405
from typing import Dict, Optional

# Third Party
import httpx
from loguru import logger


async def discover_upnp(timeout: float = 2.0) -> Dict[str, Dict[str, str]]:
    """Perform UPnP discovery via SSDP.

    Args:
        timeout: How long to wait for SSDP responses.

    Returns:
        Dictionary mapping IP addresses to discovered device info.
    """
    logger.info(f"Starting UPnP discovery (timeout={timeout}s)...")
    ssdp_msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except Exception as e:
        logger.error(f"Failed to create SSDP socket: {e}")
        return {}

    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    discovered_devices: Dict[str, Dict[str, str]] = {}

    try:
        sock.sendto(ssdp_msg.encode(), ("239.255.255.250", 1900))

        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                if ip not in discovered_devices:
                    response = data.decode("utf-8", errors="ignore")
                    location_match = [
                        line.split(": ", 1)[1]
                        for line in response.splitlines()
                        if line.lower().startswith("location:")
                    ]
                    if location_match:
                        location = location_match[0]
                        info = await _fetch_upnp_description(location)
                        if info:
                            discovered_devices[ip] = info
                            logger.debug(f"UPnP discovered: {ip} -> {info.get('modelName')}")
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.debug(f"Error receiving SSDP response: {e}")
                await asyncio.sleep(0.1)

    except Exception as e:
        logger.error(f"UPnP discovery failed: {e}")
    finally:
        sock.close()

    return discovered_devices


async def _fetch_upnp_description(url: str) -> Optional[Dict[str, str]]:
    """Fetch and parse UPnP device description XML."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=2.0)
            if resp.status_code != 200:
                return None

            # nosec: B314 - UPnP XML is generally trusted in this context
            root = ET.fromstring(resp.text)
            ns = {"ns": "urn:schemas-upnp-org:device-1-0"}

            device = root.find(".//ns:device", ns)
            if device is not None:
                info = {}
                for field in [
                    "friendlyName",
                    "manufacturer",
                    "modelName",
                    "modelNumber",
                    "serialNumber",
                ]:
                    elem = device.find(f"ns:{field}", ns)
                    if elem is not None:
                        info[field] = elem.text or ""
                return info
    except Exception as e:
        logger.debug(f"Failed to fetch UPnP description from {url}: {e}")
    return None
