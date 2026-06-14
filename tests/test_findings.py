"""Tests for core/findings.py — the render-agnostic assessment summary."""

# First Party
from edgewalker.core.findings import (
    SEVERITY_ORDER,
    AssessmentSummary,
    Finding,
    build_summary,
)


def _bundle_with_vuln_host():
    """A scan bundle: one up host with a default-cred SSH service and a CVE."""
    return {
        "port": {
            "target": "192.168.1.0/24",
            "gateway_ip": "192.168.1.1",
            "hosts": [
                {
                    "ip": "192.168.1.42",
                    "mac": "00:00:00:00:00:00",
                    "vendor": "Hikvision",
                    "state": "up",
                    "tcp": [
                        {"port": 22, "name": "ssh"},
                        {"port": 80, "name": "http"},
                    ],
                },
                {
                    "ip": "192.168.1.99",
                    "mac": "00:00:00:00:00:01",
                    "vendor": "Quiet Co",
                    "state": "down",
                    "tcp": [],
                },
            ],
        },
        "cred": {
            "results": [
                {
                    "ip": "192.168.1.42",
                    "service": "ssh",
                    "login_attempt": "successful",
                    "credentials": {"user": "admin", "password": "admin"},
                }
            ]
        },
        "cve": {
            "results": [
                {
                    "ip": "192.168.1.42",
                    "cves": [{"id": "CVE-2023-1234", "severity": "HIGH"}],
                }
            ]
        },
        "sql": {},
        "web": {},
    }


def test_build_summary_none_without_up_hosts():
    assert build_summary({"port": {"hosts": []}}) is None
    assert build_summary({}) is None


def test_build_summary_core_fields():
    summary = build_summary(_bundle_with_vuln_host())
    assert isinstance(summary, AssessmentSummary)
    # Default credentials -> instant F.
    assert summary.grade == "F"
    assert summary.target == "192.168.1.0/24"
    assert summary.gateway_ip == "192.168.1.1"
    # Only the "up" host is counted.
    assert summary.device_count == 1
    assert summary.open_ports == 2
    assert summary.devices_with_creds == 1
    assert summary.score > 0


def test_build_summary_findings_prioritised():
    summary = build_summary(_bundle_with_vuln_host())
    severities = [f.severity for f in summary.findings]
    # Critical (default creds) sorts before the HIGH CVE.
    assert severities[0] == "CRITICAL"
    assert "HIGH" in severities
    assert severities == sorted(severities, key=lambda s: SEVERITY_ORDER[s])

    creds = next(f for f in summary.findings if f.title == "Default credentials")
    assert creds.host == "192.168.1.42"
    assert "admin" in creds.detail

    cve = next(f for f in summary.findings if f.title.startswith("CVE-"))
    assert cve.severity == "HIGH"


def test_build_summary_device_rows():
    summary = build_summary(_bundle_with_vuln_host())
    assert len(summary.devices) == 1
    row = summary.devices[0]
    assert row.ip == "192.168.1.42"
    assert row.vendor == "Hikvision"
    assert row.port_count == 2
    assert row.top_service in {"ssh", "http"}
    assert row.risk_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


def test_finding_is_hashable_dataclass():
    f = Finding("LOW", "t", "1.2.3.4", "d")
    assert f.severity == "LOW"
    # frozen dataclasses are hashable
    assert hash(f) == hash(Finding("LOW", "t", "1.2.3.4", "d"))
