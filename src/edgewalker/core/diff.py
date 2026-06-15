"""Pure diff engine for EdgeWalker change tracking.

These functions are the explicit, auditable ``is_material_change`` ruleset the
plan calls for: each compares a prior observation to a new one and emits a
:class:`ChangeEvent` *only* for changes deemed material — a newly open port, a
new CVE, a credential that now passes, a grade change, a device appearing or
disappearing. Non-material churn produces nothing: DHCP-driven IP changes never
reach here because hosts are keyed by :pyattr:`Host.stable_key`, and unchanged
service banners simply don't differ.

The engine is deliberately pure — no database, no settings, no I/O. Callers
(the SQLite store) load prior state, call these functions, and persist the
results. Severity that depends on local risk weights (e.g. per-port severity)
is supplied by the caller via a callback so this module stays dependency-free
and unit-testable with hand-built inputs.
"""

from __future__ import annotations

# Standard Library
from dataclasses import dataclass, field
from typing import Callable

# Grade letters ordered best -> worst, for deciding regression vs improvement.
_GRADE_ORDER = ["A", "B", "C", "D", "F"]


@dataclass(frozen=True)
class ChangeEvent:
    """A single material change detected between two observations of a host."""

    event_type: str
    severity: str
    detail: dict = field(default_factory=dict)


def diff_ports(
    old_ports: set[int],
    new_ports: set[int],
    severity_of: Callable[[int], str],
) -> list[ChangeEvent]:
    """Emit ``port_opened`` / ``port_closed`` events for changed open ports.

    ``severity_of`` maps a port number to a severity label (the caller wires in
    the local risk weights); closed ports are informational.
    """
    events = []
    for port in sorted(new_ports - old_ports):
        events.append(ChangeEvent("port_opened", severity_of(port), {"port": port}))
    for port in sorted(old_ports - new_ports):
        events.append(ChangeEvent("port_closed", "INFO", {"port": port}))
    return events


def diff_cves(old_cve_ids: set[str], new_cves: dict[str, str]) -> list[ChangeEvent]:
    """Emit ``cve_appeared`` / ``cve_resolved`` events.

    ``new_cves`` maps CVE id -> its severity (intrinsic to the CVE).
    """
    events = []
    for cve_id in sorted(set(new_cves) - old_cve_ids):
        events.append(ChangeEvent("cve_appeared", new_cves[cve_id] or "UNKNOWN", {"cve": cve_id}))
    for cve_id in sorted(old_cve_ids - set(new_cves)):
        events.append(ChangeEvent("cve_resolved", "INFO", {"cve": cve_id}))
    return events


def diff_credentials(old_services: set[str], new_services: set[str]) -> list[ChangeEvent]:
    """Emit ``credential_exposed`` / ``credential_secured`` events per service."""
    events = []
    for svc in sorted(new_services - old_services):
        events.append(ChangeEvent("credential_exposed", "HIGH", {"service": svc}))
    for svc in sorted(old_services - new_services):
        events.append(ChangeEvent("credential_secured", "INFO", {"service": svc}))
    return events


def diff_sql(old_services: set[str], new_services: dict[str, str]) -> list[ChangeEvent]:
    """Emit ``sql_vuln_appeared`` / ``sql_vuln_resolved`` events per service.

    ``new_services`` maps a vulnerable SQL service (one with default credentials
    or anonymous access) to its severity label; resolutions are informational.
    """
    events = []
    for svc in sorted(set(new_services) - old_services):
        events.append(
            ChangeEvent("sql_vuln_appeared", new_services[svc] or "UNKNOWN", {"service": svc})
        )
    for svc in sorted(old_services - set(new_services)):
        events.append(ChangeEvent("sql_vuln_resolved", "INFO", {"service": svc}))
    return events


def diff_web(old_issues: set[str], new_issues: dict[str, str]) -> list[ChangeEvent]:
    """Emit ``web_issue_appeared`` / ``web_issue_resolved`` events per web issue.

    ``new_issues`` maps a web issue kind (``sensitive_file``, ``expired_tls`` or
    ``insecure_header``) to its severity label; resolutions are informational.
    """
    events = []
    for issue in sorted(set(new_issues) - old_issues):
        events.append(
            ChangeEvent("web_issue_appeared", new_issues[issue] or "UNKNOWN", {"issue": issue})
        )
    for issue in sorted(old_issues - set(new_issues)):
        events.append(ChangeEvent("web_issue_resolved", "INFO", {"issue": issue}))
    return events


def diff_devices(old_keys: set[str], new_keys: set[str]) -> list[ChangeEvent]:
    """Emit ``device_appeared`` / ``device_disappeared`` events.

    Returns events tagged with the host's ``stable_key`` in ``detail`` so the
    caller can attach each to the right host row.
    """
    events = []
    for key in sorted(new_keys - old_keys):
        events.append(ChangeEvent("device_appeared", "LOW", {"stable_key": key}))
    for key in sorted(old_keys - new_keys):
        events.append(ChangeEvent("device_disappeared", "INFO", {"stable_key": key}))
    return events


def diff_grade(old_grade: str | None, new_grade: str) -> list[ChangeEvent]:
    """Emit a ``grade_changed`` event when the network grade moves.

    Severity scales with how far the grade regressed; an improvement is
    informational. No event on the first-ever assessment (no prior grade).
    """
    if not old_grade or old_grade == new_grade:
        return []

    def rank(grade: str) -> int:
        return _GRADE_ORDER.index(grade) if grade in _GRADE_ORDER else len(_GRADE_ORDER)

    regressed = rank(new_grade) > rank(old_grade)
    if regressed:
        drop = rank(new_grade) - rank(old_grade)
        severity = "CRITICAL" if drop >= 3 else "HIGH" if drop == 2 else "MEDIUM"
    else:
        severity = "INFO"
    return [
        ChangeEvent(
            "grade_changed",
            severity,
            {"from": old_grade, "to": new_grade, "direction": "down" if regressed else "up"},
        )
    ]
