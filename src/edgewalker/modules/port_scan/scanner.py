"""Port Scan Module.

Wraps nmap to discover hosts and open ports on a network.
"""

from __future__ import annotations

# Standard Library
import asyncio
import ipaddress
import math
import os
import re
import socket
import subprocess  # nosec: B404
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET  # nosec: B405
from typing import Callable, Optional

# Third Party
import validators
from loguru import logger

# First Party
from edgewalker import __version__, theme, utils
from edgewalker.core.config import settings
from edgewalker.modules import ScanModule
from edgewalker.modules.mac_lookup import get_vendor
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort
from edgewalker.utils import get_device_id


class Colors:
    """ANSI color codes for terminal output."""

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
    except Exception:
        return "192.168.1.1"


def get_default_target() -> str:
    """Get default scan target (local /24 subnet)."""
    ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def validate_target(target: str) -> str | None:
    """Validate the target format to prevent command/argument injection."""
    if not target or not target.strip():
        return "Target cannot be empty"

    target = target.strip()

    # Prevent flag injection (targets starting with hyphen)
    if target.startswith("-"):
        return f"Invalid target: {target} (targets cannot start with a hyphen)"

    # CIDR Validation
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return None
        except ValueError:
            return f"Invalid CIDR range: {target}"

    # IP Validation
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        pass

    # Hostname Validation
    if validators.domain(target):
        return None

    return f"Invalid target format: {target} (expected IP, CIDR range, or valid hostname)"


def check_nmap_permissions() -> bool:
    """Check if nmap has the necessary capabilities or root privileges."""
    if os.geteuid() == 0:
        return True

    # Check for nmap capabilities (Linux only)
    if sys.platform.startswith("linux"):
        try:
            # nosec: B607, B603 - which and getcap are standard tools
            nmap_path = subprocess.check_output(["which", "nmap"], text=True).strip()
            caps = subprocess.check_output(["getcap", nmap_path], text=True)
            if "cap_net_raw" in caps and "cap_net_admin" in caps:
                return True
        except (subprocess.SubprocessError, OSError):
            pass  # nosec: B110 - best effort check for nmap capabilities

    return False


def fix_nmap_permissions() -> bool:
    """Attempt to fix nmap permissions using sudo setcap (Linux only)."""
    if not sys.platform.startswith("linux"):
        return False

    try:
        # nosec: B607, B603 - which and setcap are standard tools
        nmap_path = subprocess.check_output(["which", "nmap"], text=True).strip()
        # This will prompt for sudo password in the terminal
        cmd = ["sudo", "setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", nmap_path]
        subprocess.run(cmd, check=True)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def check_privileges() -> str | None:
    """Check for root/sudo privileges or nmap capabilities."""
    if check_nmap_permissions():
        return None

    if sys.platform.startswith("linux"):
        return (
            "Port scanning requires root privileges or nmap capabilities.\n"
            "Run 'sudo edgewalker' or apply capabilities to nmap."
        )

    return "Port scanning requires root privileges on this OS. Please run with sudo."


def get_nmap_command() -> list[str]:
    """Return the base nmap command with sudo if necessary."""
    if check_nmap_permissions():
        return ["nmap"]

    return ["sudo", "nmap"]


def _chunk_hosts(hosts: list[str], n: int) -> list[list[str]]:
    """Split *hosts* into at most *n* roughly-equal chunks."""
    if n <= 0 or not hosts:
        return [hosts] if hosts else []
    k = math.ceil(len(hosts) / n)
    return [hosts[i : i + k] for i in range(0, len(hosts), k)]


def parse_nmap_xml(xml_output: str) -> list[Host]:
    """Parse nmap XML output into host list."""
    hosts = []
    if not xml_output:
        logger.debug("Empty XML output from nmap")
        return hosts
    try:
        # nosec: B314 - nmap output is trusted in this context
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML output: {e}")
        return hosts

    for host_elem in root.findall(".//host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = ""
        mac = ""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")

        if not ip:
            continue

        hostname = ""
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        vendor = get_vendor(mac) if mac else "Unknown"

        os_matches = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch")[:3]:
                os_matches.append(osmatch.get("name", "Unknown"))

        tcp_ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                if port_elem.get("protocol") != "tcp":
                    continue

                service_elem = port_elem.find("service")
                port_info = TcpPort(
                    port=int(port_elem.get("portid", 0)),
                    name=(
                        service_elem.get("name", "unknown")
                        if service_elem is not None
                        else "unknown"
                    ),
                    product_name=(
                        service_elem.get("product", "") if service_elem is not None else ""
                    ),
                    product_version=(
                        service_elem.get("version", "") if service_elem is not None else ""
                    ),
                )
                tcp_ports.append(port_info)

        hosts.append(
            Host(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                os=os_matches,
                tcp=tcp_ports,
            )
        )
    return hosts


async def _scan_batch(
    hosts: list[str],
    ports: str | None,
    extra_flags: list[str],
    timeout: int,
    verbose: bool = False,
    batch_label: str = "",
    progress_callback: Callable[[str, str], None] | None = None,
    rich_progress: Optional[tuple[utils.Progress, utils.TaskID]] = None,
) -> tuple[str, set[str]]:
    """Run one nmap subprocess on a batch of hosts asynchronously."""
    if not hosts:
        return "", set()

    xml_fd = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    xml_path = xml_fd.name
    xml_fd.close()

    cmd = get_nmap_command() + extra_flags
    if ports:
        cmd += ["-p", ports]
    cmd += ["-oX", xml_path, "-v", "--stats-every", "10s", "--open"]
    cmd += hosts

    logger.debug(f"Executing nmap command: {' '.join(cmd)}")
    hosts_with_ports: set[str] = set()

    try:
        logger.debug(f"Starting nmap subprocess for batch {batch_label}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        async def read_output() -> None:
            if process.stdout is None:
                return
            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue

                if "Discovered open port" in line:
                    match = re.search(r"port (\d+)/(\w+) on ([\d.]+)", line)
                    if match:
                        port, proto, ip = match.groups()
                        hosts_with_ports.add(ip)
                        if verbose and not rich_progress:
                            msg = (
                                f"  {Colors.GREEN}{theme.ICON_PLUS}{Colors.RESET} "
                                f"{ip}:{port}/{proto}"
                            )
                            print(msg)
                            sys.stdout.flush()
                        if progress_callback:
                            progress_callback("port_found", f"{ip}:{port}/{proto}")

                elif "% done" in line.lower():
                    match = re.search(r"(\d+\.?\d*)%", line)
                    if match:
                        pct = float(match.group(1))
                        if rich_progress:
                            progress, task_id = rich_progress
                            progress.update(task_id, completed=pct, visible=True)
                        elif verbose:
                            tag = f" [{batch_label}]" if batch_label else ""
                            sys.stdout.write(f"\r  Scanning{tag}... {pct:.0f}%{' ' * 20}")
                            sys.stdout.flush()
                        if progress_callback:
                            progress_callback("progress", f"{pct:.0f}%")

        try:
            await asyncio.wait_for(asyncio.gather(process.wait(), read_output()), timeout=timeout)
            logger.debug(f"nmap batch {batch_label} completed with exit code {process.returncode}")
        except asyncio.TimeoutError:
            logger.warning(f"nmap batch {batch_label} timed out after {timeout}s")
            if verbose:
                print(f"\n  Scan timed out after {timeout}s, terminating nmap...")
                sys.stdout.flush()
            process.terminate()
            await process.wait()

        if rich_progress:
            progress, task_id = rich_progress
            progress.update(task_id, visible=False)

        with open(xml_path, "r") as f:
            xml_data = f.read()
        os.unlink(xml_path)

        if process.returncode != 0 and not xml_data:
            return "", hosts_with_ports

        return xml_data, hosts_with_ports

    except FileNotFoundError:
        if os.path.exists(xml_path):
            os.unlink(xml_path)
        raise
    except Exception:
        if os.path.exists(xml_path):
            os.unlink(xml_path)
        raise


async def _parallel_scan(
    live_hosts: list[str],
    ports: str | None,
    extra_flags: list[str],
    timeout: int,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
    progress: Optional[utils.Progress] = None,
) -> tuple[list[str], set[str]]:
    """Run parallel scans across hosts asynchronously."""
    if not live_hosts:
        return [], set()

    if len(live_hosts) <= 1:
        rich_progress = None
        if progress:
            task_id = progress.add_task("Scanning...", total=100, visible=False)
            rich_progress = (progress, task_id)

        xml_data, found = await _scan_batch(
            live_hosts,
            ports,
            extra_flags,
            timeout,
            verbose,
            progress_callback=progress_callback,
            rich_progress=rich_progress,
        )
        return ([xml_data] if xml_data else [], found)

    workers = min(settings.scan_workers, len(live_hosts))
    chunks = _chunk_hosts(live_hosts, workers)

    if verbose and not progress:
        print(f"  Splitting {len(live_hosts)} host(s) across {len(chunks)} parallel scan(s)")
        sys.stdout.flush()

    tasks = []
    for i, chunk in enumerate(chunks):
        rich_progress = None
        label = f"{i + 1}/{len(chunks)}"
        if progress:
            task_id = progress.add_task(f"Batch {label}", total=100, visible=False)
            rich_progress = (progress, task_id)

        tasks.append(
            _scan_batch(
                chunk,
                ports,
                extra_flags,
                timeout,
                verbose,
                label,
                progress_callback,
                rich_progress,
            )
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_xml: list[str] = []
    all_found: set[str] = set()

    for res in results:
        if isinstance(res, Exception):
            if verbose:
                print(f"\n  {Colors.YELLOW}Warning:{Colors.RESET} batch failed: {res}")
            continue
        xml_data, found = res
        if xml_data:
            all_xml.append(xml_data)
        all_found |= found

    return all_xml, all_found


async def _probe_services(
    host_ports: dict[str, list[int]],
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
    progress: Optional[utils.Progress] = None,
) -> tuple[list[str], set[str]]:
    """Run service/OS probes per host asynchronously."""
    if not host_ports:
        return [], set()

    probe_flags = ["-sV", "-O", "--osscan-guess", "-T4"]
    hosts_to_probe = list(host_ports.items())

    if len(hosts_to_probe) <= 1:
        ip, ports = hosts_to_probe[0]
        port_spec = ",".join(str(p) for p in ports)
        rich_progress = None
        if progress:
            task_id = progress.add_task(f"Probing {ip}", total=100, visible=False)
            rich_progress = (progress, task_id)

        xml_data, found = await _scan_batch(
            [ip],
            port_spec,
            probe_flags,
            settings.nmap_timeout,
            verbose,
            progress_callback=progress_callback,
            rich_progress=rich_progress,
        )
        return ([xml_data] if xml_data else [], found)

    workers = min(settings.scan_workers, len(hosts_to_probe))
    if verbose and not progress:
        print(
            f"  Probing services on {len(hosts_to_probe)} host(s) across {workers} parallel scan(s)"
        )
        sys.stdout.flush()

    tasks = []
    for ip, ports in hosts_to_probe:
        rich_progress = None
        if progress:
            task_id = progress.add_task(f"Probing {ip}", total=100, visible=False)
            rich_progress = (progress, task_id)

        tasks.append(
            _scan_batch(
                [ip],
                ",".join(str(p) for p in ports),
                probe_flags,
                settings.nmap_timeout,
                verbose,
                ip,
                progress_callback,
                rich_progress,
            )
        )

    # Limit concurrency for probing if needed, but for now gather all
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_xml: list[str] = []
    all_found: set[str] = set()

    for res in results:
        if isinstance(res, Exception):
            if verbose:
                print(f"\n  {Colors.YELLOW}Warning:{Colors.RESET} probe failed: {res}")
            continue
        xml_data, found = res
        if xml_data:
            all_xml.append(xml_data)
        all_found |= found

    return all_xml, all_found


class PortScanner(ScanModule):
    """Class-based Port Scanner using nmap."""

    name = "Port Scan"
    slug = "port_scan"
    description = "Discover hosts and open ports using nmap"

    def __init__(
        self,
        target: str | None = None,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the PortScanner.

        Args:
            target: IP, CIDR range, or hostname to scan.
            verbose: Whether to print verbose output.
            progress_callback: Optional callback for progress updates.
        """
        self.target = target or get_default_target()
        self.verbose = verbose
        self.progress_callback = progress_callback

    async def scan(self, **kwargs: object) -> PortScanModel:
        """Execute the scan asynchronously (ScanModule interface)."""
        full = kwargs.get("full", False)
        if full:
            return await self.full_scan()
        return await self.quick_scan()

    async def quick_scan(self) -> PortScanModel:
        """Perform a quick scan of common IoT ports asynchronously."""
        logger.info(f"Starting quick scan on {self.target}")
        err = validate_target(self.target)
        if err:
            raise ValueError(err)
        err = check_privileges()
        if err:
            raise PermissionError(err)

        ports = ",".join(str(p) for p in settings.iot_ports)
        if self.verbose:
            print(f"Scanning {self.target}\nPorts: {len(settings.iot_ports)} common IoT ports")
            print(f"{Colors.CYAN}-{Colors.RESET}" * 50)
            sys.stdout.flush()

        live_hosts = await ping_sweep(self.target, self.verbose, self.progress_callback)
        if not live_hosts:
            return PortScanModel(
                id=str(uuid.uuid4()),
                device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
                version=__version__,
                module="port_scan",
                module_version="0.1.0",
                hosts=[],
                all_ports=False,
                version_scan=True,
                target=self.target,
                scan_type="quick",
            )

        if self.verbose:
            print(f"{Colors.CYAN}Phase 2:{Colors.RESET} Port scan ({len(live_hosts)} host(s))")
            sys.stdout.flush()
        if self.progress_callback:
            self.progress_callback(
                "phase", f"Scanning {len(live_hosts)} device(s) for open ports..."
            )

        try:
            if self.verbose:
                with utils.get_progress() as progress:
                    all_xml, all_hosts_found = await _parallel_scan(
                        live_hosts,
                        ports,
                        ["-sV", "-T4"],
                        settings.nmap_timeout,
                        self.verbose,
                        self.progress_callback,
                        progress,
                    )
            else:
                all_xml, all_hosts_found = await _parallel_scan(
                    live_hosts,
                    ports,
                    ["-sV", "-T4"],
                    settings.nmap_timeout,
                    self.verbose,
                    self.progress_callback,
                )
        except FileNotFoundError:
            return PortScanModel(
                id=str(uuid.uuid4()),
                device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
                version=__version__,
                module="port_scan",
                module_version="0.1.0",
                hosts=[],
                all_ports=False,
                version_scan=True,
                success=False,
                error="nmap not found - please install it (brew install nmap)",
                target=self.target,
            )
        except Exception as e:
            raise RuntimeError(str(e))

        hosts_by_ip = {}
        for xml_data in all_xml:
            for host in parse_nmap_xml(xml_data):
                hosts_by_ip.setdefault(str(host.ip), host)
        hosts = list(hosts_by_ip.values())

        return PortScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
            version=__version__,
            module="port_scan",
            module_version="0.1.0",
            hosts=hosts,
            all_ports=False,
            version_scan=True,
            target=self.target,
            scan_type="quick",
            hosts_responded=len(all_hosts_found) if all_hosts_found else len(hosts),
            hosts_with_ports=len(hosts),
        )

    async def full_scan(self) -> PortScanModel:
        """Full scan using 3-phase hybrid approach asynchronously."""
        logger.info(f"Starting full scan on {self.target}")
        err = validate_target(self.target)
        if err:
            raise ValueError(err)
        err = check_privileges()
        if err:
            raise PermissionError(err)

        if self.verbose:
            print(f"Scanning {self.target}\nMode: Ping sweep + parallel nmap (3-phase)")
            print(f"{Colors.CYAN}-{Colors.RESET}" * 50)
            sys.stdout.flush()

        live_hosts = await ping_sweep(self.target, self.verbose, self.progress_callback)
        if not live_hosts:
            return PortScanModel(
                id=str(uuid.uuid4()),
                device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
                version=__version__,
                module="port_scan",
                module_version="0.1.0",
                hosts=[],
                all_ports=True,
                version_scan=True,
                target=self.target,
                scan_type="full",
            )

        if self.verbose:
            print(f"{Colors.CYAN}Phase 2:{Colors.RESET} Port discovery (SYN scan)")
            sys.stdout.flush()
        if self.progress_callback:
            self.progress_callback(
                "phase", f"Scanning {len(live_hosts)} device(s), all 65535 ports..."
            )

        try:
            if self.verbose:
                with utils.get_progress() as progress:
                    disc_xml, _ = await _parallel_scan(
                        live_hosts,
                        "1-65535",
                        ["-sS", "-T4"],
                        settings.nmap_full_timeout,
                        self.verbose,
                        self.progress_callback,
                        progress,
                    )
            else:
                disc_xml, _ = await _parallel_scan(
                    live_hosts,
                    "1-65535",
                    ["-sS", "-T4"],
                    settings.nmap_full_timeout,
                    self.verbose,
                    self.progress_callback,
                )
        except Exception:
            disc_xml = []

        disc_hosts = []
        for xml_data in disc_xml:
            disc_hosts.extend(parse_nmap_xml(xml_data))

        host_ports = {}
        for host in disc_hosts:
            ports = [p.port for p in host.tcp]
            if ports:
                host_ports[str(host.ip)] = ports

        if not host_ports:
            return PortScanModel(
                id=str(uuid.uuid4()),
                device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
                version=__version__,
                module="port_scan",
                module_version="0.1.0",
                hosts=[],
                all_ports=True,
                version_scan=True,
                target=self.target,
                scan_type="full",
                hosts_responded=len(live_hosts),
            )

        total_open = sum(len(p) for p in host_ports.values())
        if self.verbose:
            print(
                f"{Colors.CYAN}Phase 3:{Colors.RESET} Service & OS detection ({total_open} ports)"
            )
            sys.stdout.flush()
        if self.progress_callback:
            self.progress_callback("phase", f"Identifying services on {total_open} open port(s)...")

        if self.verbose:
            with utils.get_progress() as progress:
                probe_xml, _ = await _probe_services(
                    host_ports, self.verbose, self.progress_callback, progress
                )
        else:
            probe_xml, _ = await _probe_services(host_ports, self.verbose, self.progress_callback)
        hosts_by_ip = {}
        for xml_data in probe_xml:
            for host in parse_nmap_xml(xml_data):
                hosts_by_ip.setdefault(str(host.ip), host)
        hosts = list(hosts_by_ip.values())

        return PortScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if "/" not in self.target else "network-scan",
            version=__version__,
            module="port_scan",
            module_version="0.1.0",
            hosts=hosts,
            all_ports=True,
            version_scan=True,
            target=self.target,
            scan_type="full",
            hosts_responded=len(live_hosts),
            hosts_with_ports=len(hosts),
        )


# Backward compatibility wrappers
async def scan(
    target: str | None = None,
    full: bool = False,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> PortScanModel:
    """Perform a port scan asynchronously.

    Args:
        target: IP, CIDR range, or hostname to scan.
        full: Whether to perform a full scan.
        verbose: Whether to print verbose output.
        progress_callback: Optional callback for progress updates.

    Returns:
        PortScanModel with scan results.
    """
    scanner = PortScanner(target, verbose, progress_callback)
    return await scanner.full_scan() if full else await scanner.quick_scan()


async def quick_scan(
    target: str | None = None,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> PortScanModel:
    """Perform a quick scan of common IoT ports asynchronously.

    Args:
        target: IP, CIDR range, or hostname to scan.
        verbose: Whether to print verbose output.
        progress_callback: Optional callback for progress updates.

    Returns:
        PortScanModel with scan results.
    """
    return await PortScanner(target, verbose, progress_callback).quick_scan()


async def full_scan(
    target: str | None = None,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> PortScanModel:
    """Perform a full scan of all ports with OS detection asynchronously.

    Args:
        target: IP, CIDR range, or hostname to scan.
        verbose: Whether to print verbose output.
        progress_callback: Optional callback for progress updates.

    Returns:
        PortScanModel with scan results.
    """
    return await PortScanner(target, verbose, progress_callback).full_scan()


async def ping_sweep(
    target: str,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> list[str]:
    """Quick ping sweep to find live hosts asynchronously.

    Args:
        target: IP, CIDR range, or hostname to scan.
        verbose: Whether to print verbose output.
        progress_callback: Optional callback for progress updates.

    Returns:
        List of live host IP addresses.
    """
    if verbose:
        print(f"{Colors.CYAN}Phase 1:{Colors.RESET} Host discovery (ping sweep)")
        sys.stdout.flush()
    if progress_callback:
        progress_callback("phase", "Discovering devices on the network...")

    err = validate_target(target)
    if err:
        raise ValueError(err)

    cmd = get_nmap_command() + ["-sn", "-T4", target]
    logger.debug(f"Executing ping sweep: {' '.join(cmd)}")
    live_hosts = []
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        if process.stdout:
            while True:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                match = re.search(r"Nmap scan report for (?:\S+ \()?([\d.]+)\)?", line)
                if match:
                    ip = match.group(1)
                    live_hosts.append(ip)
                    if verbose:
                        print(f"  {Colors.GREEN}{theme.ICON_PLUS}{Colors.RESET} {ip}")
                        sys.stdout.flush()
                    if progress_callback:
                        progress_callback("host_found", ip)

        await process.wait()

        if verbose:
            print(f"  Found {len(live_hosts)} live host(s)\n")
        if progress_callback:
            progress_callback("phase_done", f"Found {len(live_hosts)} device(s)")
    except Exception as e:
        if verbose:
            print(f"  {Colors.YELLOW}Warning:{Colors.RESET} ping sweep failed: {e}")
    return live_hosts
