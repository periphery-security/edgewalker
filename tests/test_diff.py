# First Party
from edgewalker.core.diff import (
    diff_credentials,
    diff_cves,
    diff_devices,
    diff_grade,
    diff_ports,
    diff_sql,
    diff_web,
)


def _types(events):
    return [e.event_type for e in events]


# --- ports -----------------------------------------------------------------


def test_port_opened_and_closed():
    events = diff_ports({22, 80}, {80, 23}, severity_of=lambda p: "HIGH")
    assert _types(events) == ["port_opened", "port_closed"]
    opened = next(e for e in events if e.event_type == "port_opened")
    assert opened.detail == {"port": 23}
    assert opened.severity == "HIGH"


def test_port_severity_comes_from_callback():
    events = diff_ports(set(), {23}, severity_of=lambda p: "CRITICAL" if p == 23 else "LOW")
    assert events[0].severity == "CRITICAL"


def test_no_port_change_no_events():
    assert diff_ports({22, 80}, {22, 80}, severity_of=lambda p: "LOW") == []


# --- cves ------------------------------------------------------------------


def test_cve_appeared_carries_intrinsic_severity():
    events = diff_cves(set(), {"CVE-2024-1": "CRITICAL"})
    assert _types(events) == ["cve_appeared"]
    assert events[0].severity == "CRITICAL"
    assert events[0].detail == {"cve": "CVE-2024-1"}


def test_cve_resolved():
    events = diff_cves({"CVE-2024-1"}, {})
    assert _types(events) == ["cve_resolved"]


# --- credentials -----------------------------------------------------------


def test_credential_exposed_and_secured():
    events = diff_credentials({"ftp"}, {"ssh"})
    assert _types(events) == ["credential_exposed", "credential_secured"]
    exposed = next(e for e in events if e.event_type == "credential_exposed")
    assert exposed.severity == "HIGH"
    assert exposed.detail == {"service": "ssh"}


# --- sql --------------------------------------------------------------------


def test_sql_vuln_appeared_carries_severity():
    events = diff_sql(set(), {"mysql": "CRITICAL"})
    assert _types(events) == ["sql_vuln_appeared"]
    assert events[0].severity == "CRITICAL"
    assert events[0].detail == {"service": "mysql"}


def test_sql_vuln_resolved_is_informational():
    events = diff_sql({"redis"}, {})
    assert _types(events) == ["sql_vuln_resolved"]
    assert events[0].severity == "INFO"
    assert events[0].detail == {"service": "redis"}


def test_sql_no_change_no_events():
    assert diff_sql({"mysql"}, {"mysql": "HIGH"}) == []


# --- web --------------------------------------------------------------------


def test_web_issue_appeared_carries_severity():
    events = diff_web(set(), {"sensitive_file": "CRITICAL"})
    assert _types(events) == ["web_issue_appeared"]
    assert events[0].severity == "CRITICAL"
    assert events[0].detail == {"issue": "sensitive_file"}


def test_web_issue_appeared_and_resolved_both_directions():
    events = diff_web({"expired_tls"}, {"insecure_header": "MEDIUM"})
    assert _types(events) == ["web_issue_appeared", "web_issue_resolved"]
    resolved = next(e for e in events if e.event_type == "web_issue_resolved")
    assert resolved.severity == "INFO"
    assert resolved.detail == {"issue": "expired_tls"}


def test_web_no_change_no_events():
    assert diff_web({"insecure_header"}, {"insecure_header": "MEDIUM"}) == []


# --- devices ---------------------------------------------------------------


def test_device_appeared_and_disappeared():
    events = diff_devices({"mac:AA"}, {"mac:BB"})
    assert _types(events) == ["device_appeared", "device_disappeared"]
    assert events[0].detail == {"stable_key": "mac:BB"}


# --- grade -----------------------------------------------------------------


def test_no_grade_event_on_first_assessment():
    assert diff_grade(None, "C") == []


def test_no_grade_event_when_unchanged():
    assert diff_grade("B", "B") == []


def test_grade_regression_severity_scales_with_drop():
    assert diff_grade("A", "B")[0].severity == "MEDIUM"  # 1 step
    assert diff_grade("A", "C")[0].severity == "HIGH"  # 2 steps
    assert diff_grade("A", "F")[0].severity == "CRITICAL"  # 4 steps
    ev = diff_grade("A", "F")[0]
    assert ev.detail == {"from": "A", "to": "F", "direction": "down"}


def test_grade_improvement_is_informational():
    ev = diff_grade("D", "B")[0]
    assert ev.severity == "INFO"
    assert ev.detail["direction"] == "up"
