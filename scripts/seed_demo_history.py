"""Seed a SQLite history DB with a few assessments for demos/screenshots.

Live demo mode (``EW_DEMO_MODE=1``) returns canned scan data without persisting,
so the History view / ``history`` / ``compare`` commands would be empty. This
script writes a small, realistic sequence of scans + assessments directly into
``settings.db_path`` so those surfaces have something to show.

Point it at a throwaway location and run it before recording a demo, e.g.::

    export EW_DATA_DIR=$(mktemp -d)
    uv run python scripts/seed_demo_history.py
    uv run edgewalker history --list

``EW_DATA_DIR`` (read by ``settings`` at import) keeps it out of the real
``~/.edgewalker``. Change events for CVE/credential/web signals are
baseline-guarded (the first scan of each type emits nothing), so report #1
records an empty baseline of every type and the later reports introduce the
findings — making ``compare`` show the full spread of signals.
"""

from __future__ import annotations

# First Party
from edgewalker.core.config import settings
from edgewalker.core.sqlite_store import SqliteResultStore
from edgewalker.modules.cve_scan.models import CveModel, CveScanModel, CveScanResultModel
from edgewalker.modules.password_scan.models import (
    CredentialsModel,
    PasswordScanModel,
    PasswordScanResultModel,
    ServiceEnum,
    StatusEnum,
)
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort
from edgewalker.modules.web_scan.models import WebScanModel, WebScanResultModel

TARGET = "192.168.1.0/24"
CAMERA = {"ip": "192.168.1.10", "mac": "00:11:22:33:44:01"}
NAS = {"ip": "192.168.1.50", "mac": "00:11:22:33:44:02"}


def _ports(spec: dict, ports: list[tuple[int, str]]) -> Host:
    return Host(
        ip=spec["ip"],
        mac=spec["mac"],
        state="up",
        tcp=[TcpPort(port=p, name=n) for p, n in ports],
    )


def _port_scan(hosts: list[Host]) -> PortScanModel:
    return PortScanModel(target=TARGET, hosts=hosts)


def _cve_scan(results: list[CveScanResultModel]) -> CveScanModel:
    return CveScanModel(target=TARGET, results=results)


def _cred_scan(results: list[PasswordScanResultModel]) -> PasswordScanModel:
    return PasswordScanModel(results=results, summary={"vulnerable_hosts": len(results)})


def _web_scan(results: list[WebScanResultModel]) -> WebScanModel:
    return WebScanModel(
        id="web-demo",
        device_id="demo",
        version="1.0",
        results=results,
        summary={"total_services": len(results)},
    )


def main() -> None:
    """Write three assessments with material changes between them."""
    store = SqliteResultStore(settings.db_path)

    # Report #1 — baseline for every scan type (first of each kind => no events). Grade B.
    store.save_scan("port_scan", _port_scan([_ports(CAMERA, [(80, "http")])]))
    store.save_scan("cve_scan", _cve_scan([]))
    store.save_scan("password_scan", _cred_scan([]))
    store.save_scan("web_scan", _web_scan([]))
    store.record_assessment(TARGET, 80, "B")

    # Report #2 — a NAS appears, telnet opens on the camera, a CVE and default
    # SSH credentials show up. Grade drops to D.
    store.save_scan(
        "port_scan",
        _port_scan([_ports(CAMERA, [(80, "http"), (23, "telnet")]), _ports(NAS, [(22, "ssh")])]),
    )
    store.save_scan(
        "cve_scan",
        _cve_scan([
            CveScanResultModel(
                ip=CAMERA["ip"],
                port=80,
                service="http",
                product="lighttpd",
                version="1.4.0",
                cves=[
                    CveModel(
                        id="CVE-2024-1234",
                        description="RCE in lighttpd",
                        severity="CRITICAL",
                        score=9.8,
                    )
                ],
            )
        ]),
    )
    store.save_scan(
        "password_scan",
        _cred_scan([
            PasswordScanResultModel(
                ip=NAS["ip"],
                port=22,
                service=ServiceEnum.ssh,
                login_attempt=StatusEnum.successful,
                credentials=CredentialsModel(user="admin", password="admin"),
            )
        ]),
    )
    store.record_assessment(TARGET, 48, "D")

    # Report #3 — telnet closed again, but a sensitive file is exposed on the
    # NAS web service. Grade recovers to C.
    store.save_scan(
        "port_scan",
        _port_scan([_ports(CAMERA, [(80, "http")]), _ports(NAS, [(22, "ssh"), (443, "https")])]),
    )
    store.save_scan(
        "web_scan",
        _web_scan([
            WebScanResultModel(ip=NAS["ip"], port=443, protocol="https", sensitive_files=["/.env"])
        ]),
    )
    store.record_assessment(TARGET, 62, "C")

    print(f"Seeded {settings.db_path} with 3 assessments.")


if __name__ == "__main__":
    main()
