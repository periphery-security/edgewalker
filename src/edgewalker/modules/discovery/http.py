"""HTTP Metadata Discovery Module.

Scrapes HTTP headers and page titles to identify devices.
"""

from __future__ import annotations

# Standard Library
from typing import Optional, Tuple

# Third Party
import httpx
from bs4 import BeautifulSoup
from loguru import logger


async def discover_http(ip: str, port: int) -> Tuple[Optional[str], Optional[str]]:
    """Fetch HTTP metadata from a specific IP and port.

    Args:
        ip: IP address of the host.
        port: Port number (e.g., 80, 443, 8080).

    Returns:
        Tuple of (Server header, Page title).
    """
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}/"

    logger.debug(f"Fetching HTTP metadata from {url}")

    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(url, timeout=3.0, follow_redirects=True)
            server = resp.headers.get("Server")

            title = None
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text, "html.parser")
                if soup.title:
                    title = soup.title.string.strip() if soup.title.string else None

            if server or title:
                logger.debug(f"HTTP metadata for {ip}:{port} -> Server: {server}, Title: {title}")

            return server, title
    except Exception as e:
        logger.debug(f"Failed to fetch HTTP metadata from {url}: {e}")

    return None, None
