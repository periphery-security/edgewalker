"""CVE Scan Module.

Checks software versions from port scan against NVD (National Vulnerability Database).
"""

from __future__ import annotations

# Standard Library
import asyncio
import uuid
from typing import Callable, Optional

# Third Party
import httpx
from loguru import logger

# First Party
from edgewalker import __version__, utils
from edgewalker.core.config import settings
from edgewalker.modules import ScanModule
from edgewalker.modules.cve_scan.models import CveModel, CveScanModel, CveScanResultModel
from edgewalker.utils import get_device_id


async def search_cves_async(
    client: httpx.AsyncClient,
    product: str,
    version: Optional[str] = None,
    verbose: bool = False,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> list:
    """Search NVD for CVEs affecting a product/version asynchronously."""
    if not product:
        return []

    product = product.lower().strip()
    params = {"keywordSearch": product, "resultsPerPage": 20}
    if version:
        params["keywordSearch"] = f"{product} {version}"

    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    if semaphore is None:
        semaphore = asyncio.Semaphore(1)

    async with semaphore:
        try:
            logger.debug(f"Searching NVD for: {params['keywordSearch']}")
            response = await client.get(
                settings.nvd_api_url, params=params, headers=headers, timeout=30
            )
            logger.debug(f"NVD Response: {response.status_code}")

            if response.status_code == 403:
                # Rate limit hit, wait and retry once
                logger.warning(
                    f"NVD Rate limit hit (403). Waiting {settings.nvd_rate_limit_delay * 2}s..."
                )
                await asyncio.sleep(settings.nvd_rate_limit_delay * 2)
                response = await client.get(
                    settings.nvd_api_url, params=params, headers=headers, timeout=30
                )
                logger.debug(f"NVD Retry Response: {response.status_code}")

            if response.status_code != 200:
                logger.error(f"NVD API error: {response.status_code} - {response.text[:200]}")
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            logger.debug(
                f"Found {len(vulnerabilities)} vulnerabilities for {params['keywordSearch']}"
            )

            cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "Unknown")
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
                )

                severity = "Unknown"
                base_score = 0.0
                metrics = cve_data.get("metrics", {})
                for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss = metrics[metric_key][0].get("cvssData", {})
                        base_score = cvss.get("baseScore", 0.0)
                        severity = cvss.get("baseSeverity", "Unknown")
                        break

                cves.append({
                    "id": cve_id,
                    "description": description[:200] + "..."
                    if len(description) > 200
                    else description,
                    "severity": severity,
                    "score": base_score,
                })
            return cves
        except Exception as e:
            logger.error(f"Error searching CVEs for {product}: {e}")
            return []


class CveScanner(ScanModule):
    """Class-based CVE Scanner."""

    name = "CVE Scan"
    slug = "cve_scan"
    description = "Check discovered software versions against NVD for known CVEs"

    def __init__(
        self,
        target: str | None = None,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the CveScanner.

        Args:
            target: Target IP or range.
            verbose: Whether to print verbose output.
            progress_callback: Optional callback for progress updates.
        """
        self.target = target
        self.verbose = verbose
        self.progress_callback = progress_callback

    async def scan(self, **kwargs: object) -> CveScanModel:
        """Execute the scan asynchronously (ScanModule interface)."""
        hosts = kwargs.get("hosts", [])
        if not isinstance(hosts, list):
            hosts = []
        return await self.scan_hosts(hosts)

    async def scan_hosts(self, hosts: list) -> CveScanModel:
        """Check all services from port scan results for known CVEs asynchronously."""
        all_results = []
        services_to_check = []
        skipped_no_version = 0

        for host in hosts:
            ip = host.get("ip", "")
            mac = host.get("mac", "")
            for port_info in host.get("tcp_ports") or host.get("tcp", []):
                product = port_info.get("product") or port_info.get("product_name", "")
                version = port_info.get("version") or port_info.get("product_version", "")
                if product and version:
                    services_to_check.append({
                        "ip": ip,
                        "mac": mac,
                        "port": port_info.get("port"),
                        "service": port_info.get("service") or port_info.get("name", ""),
                        "product": product,
                        "version": version,
                    })
                elif product:
                    skipped_no_version += 1

        if self.verbose:
            if services_to_check:
                print(f"Found {len(services_to_check)} services with version info")
            if skipped_no_version > 0:
                print(f"Skipped {skipped_no_version} services (no version)")
            print()
        if self.progress_callback:
            msg = (
                f"Checking {len(services_to_check)} service(s)..."
                if services_to_check
                else "No services to check"
            )
            self.progress_callback("phase", msg)

        if not services_to_check:
            return self._build_empty_model(skipped_no_version)

        # Use a semaphore to respect NVD rate limits (e.g., max 2 concurrent requests)
        semaphore = asyncio.Semaphore(2)

        async with httpx.AsyncClient() as client:
            if self.verbose:
                with utils.get_progress() as progress:
                    task_id = progress.add_task("Checking CVEs", total=len(services_to_check))
                    tasks = []
                    for svc in services_to_check:
                        tasks.append(
                            self._scan_service(client, svc, semaphore, (progress, task_id))
                        )

                    scan_results = await asyncio.gather(*tasks)
                    all_results.extend(scan_results)
            else:
                tasks = []
                for svc in services_to_check:
                    tasks.append(self._scan_service(client, svc, semaphore))

                scan_results = await asyncio.gather(*tasks)
                all_results.extend(scan_results)

        summary = {
            "total_services": len(all_results),
            "services_with_version": len(all_results),
            "services_without_version": skipped_no_version,
            "services_with_cves": len([r for r in all_results if r.cves]),
            "total_cves": sum(len(r.cves) for r in all_results),
            "critical_cves": sum(
                len([c for c in r.cves if c.severity == "CRITICAL"]) for r in all_results
            ),
            "high_cves": sum(len([c for c in r.cves if c.severity == "HIGH"]) for r in all_results),
            "skipped_no_version": skipped_no_version,
        }

        return CveScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
            version=__version__,
            module="cve_scan",
            module_version="0.1.0",
            results=all_results,
            summary=summary,
        )

    async def _scan_service(
        self,
        client: httpx.AsyncClient,
        svc: dict,
        semaphore: asyncio.Semaphore,
        rich_progress: Optional[tuple[utils.Progress, utils.TaskID]] = None,
    ) -> CveScanResultModel:
        """Scan a single service for CVEs asynchronously."""
        logger.debug(f"Checking {svc['product']} {svc['version']} on {svc['ip']}:{svc['port']}")
        if self.progress_callback:
            self.progress_callback(
                "cve_check",
                f"Checking {svc['product']} {svc['version']} on {svc['ip']}:{svc['port']}",
            )

        if rich_progress:
            progress, task_id = rich_progress
            progress.update(task_id, description=f"Checking {svc['product']} {svc['version']}")

        cve_dicts = await search_cves_async(
            client, svc["product"], svc["version"], self.verbose, semaphore
        )

        cves = [
            CveModel(
                id=c["id"],
                description=c.get("description", ""),
                severity=c["severity"],
                score=c["score"],
            )
            for c in cve_dicts
        ]

        if cves and self.progress_callback:
            self.progress_callback(
                "cve_found",
                f"{len(cves)} CVE(s) found for {svc['product']} {svc['version']}",
            )

        if rich_progress:
            progress, task_id = rich_progress
            progress.update(task_id, advance=1)

        return CveScanResultModel(
            ip=svc["ip"],
            port=svc["port"],
            service=svc["service"],
            product=svc["product"],
            version=svc["version"],
            cves=cves,
        )

    def _build_empty_model(self, skipped_no_version: int) -> CveScanModel:
        return CveScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
            version=__version__,
            module="cve_scan",
            module_version="0.1.0",
            results=[],
            summary={
                "total_services": 0,
                "services_with_version": 0,
                "services_without_version": skipped_no_version,
                "services_with_cves": 0,
                "total_cves": 0,
                "critical_cves": 0,
                "high_cves": 0,
                "skipped_no_version": skipped_no_version,
            },
        )


async def search_cves(product: str, version: Optional[str] = None, verbose: bool = False) -> list:
    """Search CVEs asynchronously."""
    if not product:
        return []

    async with httpx.AsyncClient() as client:
        return await search_cves_async(client, product, version, verbose)


# Backward compatibility


async def scan(
    hosts: list,
    target: str | None = None,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> CveScanModel:
    """Perform a CVE scan asynchronously.

    Args:
        hosts: List of hosts to scan.
        target: Target IP or range.
        verbose: Whether to print verbose output.
        progress_callback: Optional callback for progress updates.

    Returns:
        CveScanModel with scan results.
    """
    return await CveScanner(target, verbose, progress_callback).scan_hosts(hosts)
