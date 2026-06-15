"""EdgeWalker findings — render-agnostic assessment summary.

Turns the persisted scan bundle (see :meth:`Engine.load_report_inputs`) into a
plain-data :class:`AssessmentSummary`: the overall grade, network stats, a
flat list of prioritised :class:`Finding` items, and per-device rows.

This is the single source of truth the redesigned TUI dashboard renders, and
is intended to back a future ``edgewalker findings`` CLI command too. It holds
no Rich/Textual types — only dataclasses and primitives.
"""

from __future__ import annotations

# Standard Library
from dataclasses import dataclass, field
from typing import Any, Optional

# First Party
from edgewalker.core.risk import RiskEngine
from edgewalker.modules.sql_scan.models import SQL_VULNERABLE_STATUSES

#: Sort weight for severities (lower sorts first / most severe).
SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class Finding:
    """A single prioritised security issue."""

    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    host: str
    detail: str = ""


@dataclass(frozen=True)
class DeviceRow:
    """A device as shown in the dashboard device table."""

    ip: str
    vendor: str
    port_count: int
    top_service: str
    score: int
    risk_level: str  # CRITICAL | HIGH | MEDIUM | LOW | NONE


@dataclass
class AssessmentSummary:
    """Everything the dashboard overview needs, as plain data."""

    grade: str
    grade_reason: str
    score: int
    target: str
    device_count: int
    open_ports: int
    gateway_ip: Optional[str]
    devices_with_creds: int
    findings: list[Finding] = field(default_factory=list)
    devices: list[DeviceRow] = field(default_factory=list)


def _cve_severity(raw: str) -> str:
    """Normalise an NVD severity label to our four-level scale."""
    label = (raw or "").upper()
    return label if label in SEVERITY_ORDER else "MEDIUM"


def _device_findings(ip: str, risk: dict[str, Any]) -> list[Finding]:
    """Derive findings for a single device from its risk dict."""
    out: list[Finding] = []

    for cred in risk.get("raw_weak_creds", []):
        if isinstance(cred, dict):
            service = cred.get("service", "unknown")
            detail = f"{cred.get('user', '?')} / {cred.get('password', '?')} · {service}"
        else:
            service = str(cred)
            detail = f"via {service}"
        out.append(Finding("CRITICAL", "Default credentials", ip, detail))

    for cve in risk.get("raw_cves", []):
        cve_id = cve.get("id", "CVE") if isinstance(cve, dict) else str(cve)
        sev = _cve_severity(cve.get("severity", "") if isinstance(cve, dict) else "")
        out.append(Finding(sev, cve_id, ip, "Known vulnerability"))

    for res in risk.get("sql_findings", []):
        status = res.get("status")
        if status in SQL_VULNERABLE_STATUSES:
            service = res.get("service", "database")
            label = "Default credentials" if status == "successful" else "Anonymous access"
            out.append(Finding("HIGH", f"{label} · {service}", ip, "Unsecured SQL service"))

    for res in risk.get("web_findings", []):
        if res.get("sensitive_files"):
            out.append(Finding("HIGH", "Sensitive files exposed", ip, "Web service"))
        if res.get("tls") and res["tls"].get("expired"):
            out.append(Finding("MEDIUM", "Expired TLS certificate", ip, "Web service"))
        headers = res.get("headers", {})
        if not headers.get("csp") or not headers.get("hsts"):
            out.append(Finding("LOW", "Missing security headers", ip, "Web service"))

    return out


def _top_service(open_ports: list[str]) -> str:
    """Pick the most representative service label from ``port/name`` strings."""
    if not open_ports:
        return "—"
    # open_ports are formatted "port/name"; surface the name of the first.
    first = open_ports[0]
    return first.split("/", 1)[1] if "/" in first else first


def build_summary(inputs: dict[str, dict]) -> Optional[AssessmentSummary]:
    """Build an :class:`AssessmentSummary` from a persisted scan bundle.

    Args:
        inputs: The dict returned by ``Engine.load_report_inputs`` (keys
            ``port``, ``cred``, ``cve``, ``sql``, ``web``).

    Returns:
        The summary, or ``None`` when there is no usable port-scan data.
    """
    port = inputs.get("port") or {}
    hosts = [h for h in port.get("hosts", []) if h.get("state", "up") == "up"]
    if not hosts:
        return None

    engine = RiskEngine(
        port,
        inputs.get("cred") or {},
        inputs.get("cve") or {},
        inputs.get("sql") or {},
        inputs.get("web") or {},
    )

    device_reports: list[dict[str, Any]] = []
    findings: list[Finding] = []
    devices: list[DeviceRow] = []
    open_port_total = 0

    for host in hosts:
        ip = str(host.get("ip", ""))
        if not ip:
            continue
        risk = engine.calculate_device_risk(ip)
        device_reports.append({"ip": ip, "risk": risk})

        open_ports = risk.get("open_ports", [])
        open_port_total += len(open_ports)
        devices.append(
            DeviceRow(
                ip=ip,
                vendor=host.get("vendor", "Unknown"),
                port_count=len(open_ports),
                top_service=_top_service(open_ports),
                score=risk.get("score", 0),
                risk_level=risk.get("risk_level", "NONE"),
            )
        )
        findings.extend(_device_findings(ip, risk))

    devices.sort(key=lambda d: d.score, reverse=True)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    grade, reason, _ = RiskEngine.calculate_network_grade(device_reports)
    overall_score = max((d.score for d in devices), default=0)
    devices_with_creds = sum(
        1 for d in device_reports if d["risk"].get("factors", {}).get("credentials", 0) > 0
    )

    return AssessmentSummary(
        grade=grade,
        grade_reason=reason,
        score=overall_score,
        target=port.get("target", ""),
        device_count=len(devices),
        open_ports=open_port_total,
        gateway_ip=port.get("gateway_ip"),
        devices_with_creds=devices_with_creds,
        findings=findings,
        devices=devices,
    )
