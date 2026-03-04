"""Password Scan Module.

Tests default/weak credentials against SSH, FTP, Telnet, and SMB services.
Utilizes asyncio and asyncssh for high-performance scanning.
"""

from __future__ import annotations

# Standard Library
import asyncio
import contextlib
import csv
import ftplib
import os
import socket
import sys
import uuid
from abc import ABC, abstractmethod
from typing import Callable, Optional, Union

# Third Party
import asyncssh
from impacket.smbconnection import SMBConnection

# First Party
from edgewalker import __version__, theme, utils
from edgewalker.core.config import settings
from edgewalker.modules import ScanModule
from edgewalker.modules.password_scan.models import (
    CredentialsModel,
    PasswordScanModel,
    PasswordScanResultModel,
    ServiceEnum,
    StatusEnum,
)
from edgewalker.utils import get_device_id

# Path to bundled credential database
CREDS_CSV = settings.creds_file


class Colors:
    """ANSI color codes for terminal output."""

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class SuppressStderr:
    """Context manager to suppress stderr output (for noisy libraries)."""

    def __enter__(self) -> SuppressStderr:
        """Redirect stderr to devnull."""
        self._stack = contextlib.ExitStack()
        self._devnull = self._stack.enter_context(open(os.devnull, "w"))
        self._stack.enter_context(contextlib.redirect_stderr(self._devnull))
        return self

    def __exit__(self, *args: object) -> None:
        """Restore stderr."""
        self._stack.close()


def check_port_open(host: str, port: int, timeout: int = settings.conn_timeout) -> bool:
    """Check if a port is open on a host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            res = sock.connect_ex((host, port))
            return res == 0
    except Exception:
        return False


class AsyncServiceScanner(ABC):
    """Abstract base class for asynchronous service scanners."""

    def __init__(
        self,
        ip: str,
        port: int,
        mac: str = "",
        top_n: Optional[int] = None,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
        semaphore: Optional[asyncio.Semaphore] = None,
        rich_progress: Optional[tuple[utils.Progress, utils.TaskID]] = None,
    ) -> None:
        """Initialize the AsyncServiceScanner.

        Args:
            ip: Target IP address.
            port: Target port number.
            mac: Target MAC address.
            top_n: Number of top credentials to test.
            verbose: Whether to print verbose output.
            progress_callback: Optional callback for progress updates.
            semaphore: Optional semaphore to limit concurrency.
            rich_progress: Optional tuple of (Progress, TaskID) for Rich progress bars.
        """
        self.ip = ip
        self.port = port
        self.mac = mac
        self.top_n = top_n
        self.verbose = verbose
        self.progress_callback = progress_callback
        self.semaphore = semaphore or asyncio.Semaphore(settings.cred_workers)
        self.rich_progress = rich_progress

    @abstractmethod
    def service_name(self) -> str:
        """Return the name of the service."""
        ...

    @abstractmethod
    def service_enum(self) -> ServiceEnum:
        """Return the service enum."""
        ...

    @abstractmethod
    async def attempt_login(
        self, username: str, password: str
    ) -> tuple[Union[bool, StatusEnum], bool]:
        """Attempt login. Returns (success/status, kill_loop)."""
        ...

    async def is_port_open(self) -> bool:
        """Check if port is open with a short timeout."""
        return await asyncio.to_thread(check_port_open, self.ip, self.port, timeout=2)

    async def scan(self) -> PasswordScanResultModel:
        """Perform the scan."""
        # Use a shorter timeout for the initial port check to avoid hanging
        if not await self.is_port_open():
            if self.rich_progress:
                progress, task_id = self.rich_progress
                progress.update(task_id, visible=False)
            return PasswordScanResultModel(
                ip=self.ip,
                port=self.port,
                service=self.service_enum(),
                login_attempt=StatusEnum.unknown,
                error="port_closed",
            )

        creds = load_credentials(self.service_name(), self.top_n)
        if self.progress_callback:
            self.progress_callback(
                "service_start",
                f"{self.ip} {self.service_name().upper()}:{self.port} "
                f"-- testing {len(creds)} credentials",
            )

        if self.rich_progress:
            progress, task_id = self.rich_progress
            progress.update(task_id, total=len(creds), visible=True)

        found_cred = None
        login_status = StatusEnum.failed

        for i, (user, pw) in enumerate(creds):
            if self.rich_progress:
                progress, task_id = self.rich_progress
                progress.update(
                    task_id,
                    advance=1,
                    description=f"{self.ip} {self.service_name().upper()} ({user})",
                )

            # Notify progress more frequently for better UX
            if self.progress_callback:
                pct = int((i + 1) / len(creds) * 100)
                self.progress_callback(
                    "cred_progress", f"{self.ip} {self.service_name().upper()} -- {pct}% ({user})"
                )

            async with self.semaphore:
                try:
                    # Add a timeout to the login attempt itself
                    result, kill_loop = await asyncio.wait_for(
                        self.attempt_login(user, pw), timeout=settings.conn_timeout + 2
                    )
                except asyncio.TimeoutError:
                    result, kill_loop = StatusEnum.failed, False

            if result is True:
                login_status = StatusEnum.successful
                found_cred = CredentialsModel(user=user, password=pw)
                if self.verbose and not self.rich_progress:
                    print(
                        f"\r  {Colors.RED}{theme.ICON_PLUS}{Colors.RESET} {self.ip} "
                        f"{self.service_name().upper()} "
                        f"{Colors.YELLOW}{user}:{pw}{Colors.RESET}{' ' * 20}"
                    )
                    sys.stdout.flush()

                if self.progress_callback:
                    self.progress_callback(
                        "cred_found", f"{self.ip} {self.service_name().upper()} -- {user}:{pw}"
                    )
                break
            elif result == StatusEnum.ratelimit:
                login_status = StatusEnum.ratelimit
                break

            if kill_loop:
                break

        if self.rich_progress:
            progress, task_id = self.rich_progress
            progress.update(task_id, visible=False)

        return PasswordScanResultModel(
            ip=self.ip,
            port=self.port,
            service=self.service_enum(),
            login_attempt=login_status,
            credentials=found_cred,
            tested_count=i + 1,
        )


class SSHScanner(AsyncServiceScanner):
    """SSH credential scanner."""

    def service_name(self) -> str:
        """Return the service name."""
        return "ssh"

    def service_enum(self) -> ServiceEnum:
        """Return the service enum."""
        return ServiceEnum.ssh

    async def attempt_login(self, username: str, password: str) -> tuple[bool, bool]:
        """Attempt SSH login."""
        try:
            async with asyncssh.connect(
                self.ip,
                port=self.port,
                username=username,
                password=password,
                known_hosts=None,
                login_timeout=settings.conn_timeout,
            ):
                return True, False
        except Exception:
            return False, False


class FTPScanner(AsyncServiceScanner):
    """FTP credential scanner."""

    def service_name(self) -> str:
        """Return the service name."""
        return "ftp"

    def service_enum(self) -> ServiceEnum:
        """Return the service enum."""
        return ServiceEnum.ftp

    async def attempt_login(self, username: str, password: str) -> tuple[bool, bool]:
        """Attempt FTP login."""
        try:
            # ftplib is synchronous, run in thread
            def _ftp_login() -> bool:
                with ftplib.FTP() as ftp:
                    ftp.connect(self.ip, self.port, timeout=settings.conn_timeout)
                    ftp.login(username, password)
                    return True

            return await asyncio.to_thread(_ftp_login), False
        except Exception:
            return False, False


class TelnetScanner(AsyncServiceScanner):
    """Telnet credential scanner using raw sockets."""

    def service_name(self) -> str:
        """Return the service name."""
        return "telnet"

    def service_enum(self) -> ServiceEnum:
        """Return the service enum."""
        return ServiceEnum.telnet

    async def attempt_login(self, username: str, password: str) -> tuple[bool, bool]:
        """Attempt Telnet login."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port), timeout=settings.conn_timeout
            )

            async def _read_until(patterns: list[bytes]) -> tuple[int, bytes]:
                buf = b""
                while True:
                    try:
                        data = await asyncio.wait_for(
                            reader.read(1024), timeout=settings.conn_timeout
                        )
                    except asyncio.TimeoutError:
                        return -1, buf

                    if not data:
                        return -1, buf
                    buf += data
                    for i, p in enumerate(patterns):
                        if p in buf:
                            return i, buf
                    if len(buf) > 4096:
                        return -1, buf

            # Wait for login prompt
            idx, _ = await _read_until([b"login:", b"user:", b"Username:"])
            if idx == -1:
                writer.close()
                await writer.wait_closed()
                return False, False

            writer.write(username.encode() + b"\n")
            await writer.drain()

            # Wait for password prompt
            idx, _ = await _read_until([b"password:", b"Password:"])
            if idx == -1:
                writer.close()
                await writer.wait_closed()
                return False, False

            writer.write(password.encode() + b"\n")
            await writer.drain()

            # Check for success
            idx, _ = await _read_until([b"Welcome", b"$", b"#", b">", b"Login incorrect"])
            success = idx != -1 and idx != 4

            writer.close()
            await writer.wait_closed()
            return success, False
        except Exception:
            return False, False


class SMBScanner(AsyncServiceScanner):
    """SMB credential scanner."""

    def service_name(self) -> str:
        """Return the service name."""
        return "smb"

    def service_enum(self) -> ServiceEnum:
        """Return the service enum."""
        return ServiceEnum.smb

    async def attempt_login(self, username: str, password: str) -> tuple[bool, bool]:
        """Attempt SMB login."""
        try:

            def _smb_login() -> bool:
                with SuppressStderr():
                    conn = SMBConnection(self.ip, self.ip, sess_port=self.port)
                    conn.login(username, password)
                    return True

            return await asyncio.to_thread(_smb_login), False
        except Exception:
            return False, False


class PasswordScanner(ScanModule):
    """Coordinator for password scanning."""

    name = "Password Scan"
    slug = "password_scan"
    description = "Test default/weak credentials against discovered services"

    def __init__(
        self,
        target: str | None = None,
        top_n: Optional[int] = 10,
        verbose: bool = False,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the PasswordScanner.

        Args:
            target: Target IP or range.
            top_n: Number of top credentials to test.
            verbose: Whether to print verbose output.
            progress_callback: Optional callback for progress updates.
        """
        self.target = target
        self.top_n = top_n
        self.verbose = verbose
        self.progress_callback = progress_callback
        self.port_map = {21: FTPScanner, 22: SSHScanner, 23: TelnetScanner, 445: SMBScanner}
        # Limit total concurrent login attempts across all hosts/services
        self.semaphore = asyncio.Semaphore(settings.cred_workers)

    async def scan(self, **kwargs: object) -> PasswordScanModel:
        """Execute the scan asynchronously (ScanModule interface)."""
        hosts = kwargs.get("hosts", [])
        if not isinstance(hosts, list):
            hosts = []
        return await self.scan_hosts(hosts)

    async def scan_host(
        self, host: str, mac: str, ports: dict[str, int], progress: Optional[utils.Progress] = None
    ) -> list[PasswordScanResultModel]:
        """Scan a single host for default credentials asynchronously.

        Args:
            host: Target IP address.
            mac: Target MAC address.
            ports: Dictionary of service names to port numbers.
            progress: Optional Rich Progress object.

        Returns:
            List of PasswordScanResultModel.
        """
        tasks = []
        for svc, port in ports.items():
            scanner_cls = self.port_map.get(port)
            if not scanner_cls:
                if svc == "ssh":
                    scanner_cls = SSHScanner
                elif svc == "ftp":
                    scanner_cls = FTPScanner
                elif svc == "telnet":
                    scanner_cls = TelnetScanner
                elif svc == "smb":
                    scanner_cls = SMBScanner

            if scanner_cls:
                rich_progress = None
                if progress:
                    task_id = progress.add_task(f"{host} {svc.upper()}", total=None, visible=False)
                    rich_progress = (progress, task_id)

                scanner = scanner_cls(
                    host,
                    port,
                    mac,
                    self.top_n,
                    self.verbose,
                    self.progress_callback,
                    self.semaphore,
                    rich_progress,
                )
                tasks.append(scanner.scan())

        if not tasks:
            return []
        return await asyncio.gather(*tasks)

    async def scan_hosts(self, hosts: list) -> PasswordScanModel:
        """Scan multiple hosts for default credentials asynchronously.

        Args:
            hosts: List of hosts to scan.

        Returns:
            PasswordScanModel with results.
        """
        all_results = []
        seen_ips = set()
        work_data = []

        for h in hosts:
            if isinstance(h, dict):
                ip = h.get("ip", "")
                mac = h.get("mac", "")
            else:
                # Handle Host object or other types
                ip = str(getattr(h, "ip", h))
                mac = str(getattr(h, "mac", ""))

            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)

            ports = {}
            if isinstance(h, dict):
                for p in h.get("tcp_ports") or h.get("tcp", []):
                    pn = p.get("port")
                    if pn == 21:
                        ports["ftp"] = 21
                    elif pn == 22:
                        ports["ssh"] = 22
                    elif pn == 23:
                        ports["telnet"] = 23
                    elif pn == 445:
                        ports["smb"] = 445
            else:
                # Handle Host object
                for p in getattr(h, "tcp", []):
                    pn = p.port
                    if pn == 21:
                        ports["ftp"] = 21
                    elif pn == 22:
                        ports["ssh"] = 22
                    elif pn == 23:
                        ports["telnet"] = 23
                    elif pn == 445:
                        ports["smb"] = 445

            if not ports and not isinstance(h, dict):
                # Fallback for simple string/IP inputs
                ports = {"ssh": 22, "ftp": 21, "telnet": 23}

            if ports:
                work_data.append((ip, mac, ports))

        if not work_data:
            return PasswordScanModel(
                id=str(uuid.uuid4()),
                device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
                version=__version__,
                module="password_scan",
                module_version="0.1.0",
                results=[],
                summary={
                    "total_hosts": 0,
                    "vulnerable_hosts": 0,
                    "services_tested": 0,
                    "credentials_found": 0,
                },
            )

        if self.verbose and len(work_data) > 1:
            print(f"  Testing {len(work_data)} hosts (async)")

        if self.verbose:
            with utils.get_progress() as progress:
                work = [self.scan_host(ip, mac, ports, progress) for ip, mac, ports in work_data]
                host_results = await asyncio.gather(*work)
        else:
            work = [self.scan_host(ip, mac, ports) for ip, mac, ports in work_data]
            host_results = await asyncio.gather(*work)

        for res_list in host_results:
            all_results.extend(res_list)

        vuln_hosts = len(
            set(str(r.ip) for r in all_results if r.login_attempt == StatusEnum.successful)
        )
        creds_found = len([r for r in all_results if r.login_attempt == StatusEnum.successful])

        summary = {
            "total_hosts": len(work_data),
            "vulnerable_hosts": vuln_hosts,
            "services_tested": len(all_results),
            "credentials_found": creds_found,
        }

        return PasswordScanModel(
            id=str(uuid.uuid4()),
            device_id=get_device_id(self.target) if hasattr(self, "target") else "network-scan",
            version=__version__,
            module="password_scan",
            module_version="0.1.0",
            results=all_results,
            summary=summary,
        )


# --- Credential Loading Logic ---
_cred_cache: dict[str, list] = {}
_printed_services: set[str] = set()


def _load_csv() -> dict[str, list[tuple[str, str]]]:
    result = {}
    if not CREDS_CSV.exists():
        return result
    with open(CREDS_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            svc = row.get("service", "").strip().lower()
            if svc:
                result.setdefault(svc, []).append((row.get("user", ""), row.get("password", "")))
    return result


def load_credentials(service: str, top_n: Optional[int] = None) -> list:
    """Load credentials for a service.

    Args:
        service: Service name.
        top_n: Number of top credentials to return.

    Returns:
        List of (username, password) tuples.
    """
    if not _cred_cache:
        _cred_cache.update(_load_csv())
    creds = _cred_cache.get(service, [])
    if not creds:
        print(f"  {Colors.YELLOW}!!{Colors.RESET} No {service.upper()} credentials found")
    elif service not in _printed_services:
        _printed_services.add(service)
        msg = (
            f"  {Colors.GREEN}{theme.ICON_PLUS}{Colors.RESET} "
            f"Loaded {len(creds)} {service.upper()} credentials"
        )
        print(msg)
    return creds[:top_n] if top_n else creds


# --- Backward Compatibility ---
async def _test_service(
    host: str,
    service: str,
    port: int,
    test_func: Callable,
    top_n: Optional[int],
    verbose: bool,
    progress_callback: Callable[[str, str], None] | None = None,
) -> PasswordScanResultModel:
    """Backward compatible _test_service asynchronously."""
    scanner_cls = {21: FTPScanner, 22: SSHScanner, 23: TelnetScanner, 445: SMBScanner}.get(port)
    if not scanner_cls:
        if service == "ssh":
            scanner_cls = SSHScanner
        elif service == "ftp":
            scanner_cls = FTPScanner
        elif service == "telnet":
            scanner_cls = TelnetScanner
        elif service == "smb":
            scanner_cls = SMBScanner

    if not scanner_cls:
        raise ValueError(f"Unsupported service: {service}")
    scanner = scanner_cls(host, port, "", top_n, verbose, progress_callback)
    return await scanner.scan()


async def scan(
    hosts: list,
    target: str | None = None,
    top_n: int = 10,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> PasswordScanModel:
    """Backward compatible scan function asynchronously."""
    scanner = PasswordScanner(target, top_n, verbose, progress_callback)
    return await scanner.scan_hosts(hosts)


async def scan_host(
    host: str,
    ports: dict,
    target: str | None = None,
    top_n: int = 10,
    verbose: bool = False,
    progress_callback: Callable[[str, str], None] | None = None,
) -> dict:
    """Backward compatible scan_host function asynchronously."""
    scanner = PasswordScanner(target, top_n, verbose, progress_callback)
    results = await scanner.scan_host(host, ports)
    out = {"host": host, "services": {}}
    for r in results:
        status = "vulnerable" if r.login_attempt == StatusEnum.successful else "secure"
        if r.error == "port_closed":
            status = "port_closed"
        out["services"][str(r.service.value)] = {
            "port": r.port,
            "status": status,
            "tested": 10,
            "credentials": [{"username": r.credentials.user, "password": r.credentials.password}]
            if r.credentials
            else [],
        }
    return out


async def test_ssh(h: str, p: int, u: str, pw: str) -> bool:
    """Backward compatible test_ssh asynchronously."""
    res, _ = await SSHScanner(h, p).attempt_login(u, pw)
    return res is True


async def test_ftp(h: str, p: int, u: str, pw: str) -> bool:
    """Backward compatible test_ftp asynchronously."""
    res, _ = await FTPScanner(h, p).attempt_login(u, pw)
    return res is True


async def test_smb(h: str, p: int, u: str, pw: str) -> bool:
    """Backward compatible test_smb asynchronously."""
    res, _ = await SMBScanner(h, p).attempt_login(u, pw)
    return res is True


async def test_telnet(h: str, p: int, u: str, pw: str) -> bool:
    """Backward compatible test_telnet asynchronously."""
    res, _ = await TelnetScanner(h, p).attempt_login(u, pw)
    return res is True


def init_cache(d: object) -> None:
    """Backward compatible init_cache."""
    pass
