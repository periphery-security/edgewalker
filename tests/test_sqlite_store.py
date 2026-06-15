# Standard Library
import json
import sqlite3

# Third Party
import pytest

# First Party
from edgewalker.core.result_store import ResultStore
from edgewalker.core.sqlite_store import SCHEMA_VERSION, SqliteResultStore
from edgewalker.modules.cve_scan.models import CveModel, CveScanModel, CveScanResultModel
from edgewalker.modules.password_scan.models import (
    CredentialsModel,
    PasswordScanModel,
    PasswordScanResultModel,
    ServiceEnum,
    StatusEnum,
)
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort
from edgewalker.modules.sql_scan.models import SqlScanModel, SqlScanResultModel
from edgewalker.modules.web_scan.models import (
    SecurityHeadersModel,
    TlsInfoModel,
    WebScanModel,
    WebScanResultModel,
)


@pytest.fixture
def store(tmp_path):
    return SqliteResultStore(tmp_path / "edgewalker.db")


def _port_scan() -> PortScanModel:
    host = Host(
        ip="192.168.1.10",
        mac="00:11:22:33:44:55",
        hostname="camera",
        state="up",
        tcp=[TcpPort(port=80, name="http", product_name="lighttpd", product_version="1.4")],
    )
    return PortScanModel(target="192.168.1.0/24", hosts=[host])


def test_satisfies_protocol(store):
    assert isinstance(store, ResultStore)


def test_schema_version_is_stamped(tmp_path):
    db = tmp_path / "edgewalker.db"
    SqliteResultStore(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_init_is_idempotent(tmp_path):
    db = tmp_path / "edgewalker.db"
    SqliteResultStore(db)
    # Re-opening the same DB must not error or wipe anything.
    SqliteResultStore(db).save_scan("port_scan", _port_scan())
    again = SqliteResultStore(db)
    assert again.get_latest_port_scan() is not None


def test_save_port_scan_populates_hosts_and_state(store):
    store.save_scan("port_scan", _port_scan())
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        hosts = conn.execute("SELECT * FROM hosts").fetchall()
        assert len(hosts) == 1
        assert hosts[0]["stable_key"] == "mac:00:11:22:33:44:55"
        state = conn.execute("SELECT * FROM host_state").fetchone()
        assert state is not None
        port_findings = conn.execute("SELECT * FROM findings WHERE kind = 'port'").fetchall()
        assert len(port_findings) == 1
        assert port_findings[0]["ref"] == "80"


def test_get_latest_port_scan_roundtrip(store):
    store.save_scan("port_scan", _port_scan())
    loaded = store.get_latest_port_scan()
    assert loaded is not None
    assert loaded.target == "192.168.1.0/24"
    assert len(loaded.hosts) == 1
    h = loaded.hosts[0]
    assert str(h.ip) == "192.168.1.10"
    assert h.mac == "00:11:22:33:44:55"
    assert h.stable_key == "mac:00:11:22:33:44:55"
    assert [p.port for p in h.tcp] == [80]


def test_get_latest_port_scan_none_when_empty(store):
    assert store.get_latest_port_scan() is None


def test_host_is_stable_across_rescans(store):
    """Re-scanning the same host (new IP) must not create a second host row."""
    store.save_scan("port_scan", _port_scan())
    moved = _port_scan()
    moved.hosts[0].ip = "192.168.1.99"  # DHCP changed the IP; MAC is stable
    store.save_scan("port_scan", moved)
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


def test_save_cve_findings_linked_to_host(store):
    store.save_scan("port_scan", _port_scan())
    cve = CveScanModel(
        target="192.168.1.0/24",
        results=[
            CveScanResultModel(
                ip="192.168.1.10",
                port=80,
                service="http",
                product="lighttpd",
                version="1.4",
                cves=[CveModel(id="CVE-2024-1", description="x", severity="HIGH", score=7.5)],
            )
        ],
    )
    store.save_scan("cve_scan", cve)
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM findings WHERE kind = 'cve'").fetchone()
        assert row["ref"] == "CVE-2024-1"
        assert row["severity"] == "HIGH"
        assert row["host_id"] is not None  # resolved to the port-scanned host


def test_save_credential_findings_only_for_successful(store):
    store.save_scan("port_scan", _port_scan())
    pwd = PasswordScanModel(
        results=[
            PasswordScanResultModel(
                ip="192.168.1.10",
                port=22,
                service=ServiceEnum.ssh,
                login_attempt=StatusEnum.successful,
                credentials=CredentialsModel(user="admin", password="admin"),
            ),
            PasswordScanResultModel(
                ip="192.168.1.10",
                port=21,
                service=ServiceEnum.ftp,
                login_attempt=StatusEnum.failed,
            ),
        ]
    )
    store.save_scan("password_scan", pwd)
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute("SELECT * FROM findings WHERE kind = 'cred'").fetchall()
        assert len(rows) == 1  # only the successful login is a finding


def test_record_assessment_writes_score_row(store):
    store.record_assessment("192.168.1.0/24", 72.5, "C")
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE scan_type = 'assessment'").fetchone()
        assert row["overall_score"] == 72.5
        assert row["grade"] == "C"


def _assessment_rows(store):
    with sqlite3.connect(store.db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'assessment'").fetchone()[
            0
        ]


def test_record_assessment_dedupes_unchanged_snapshot(store):
    """Repeated identical snapshots collapse to a single trend point."""
    store.record_assessment("192.168.1.0/24", 72.0, "C")
    store.record_assessment("192.168.1.0/24", 72.0, "C")
    assert _assessment_rows(store) == 1


def test_record_assessment_records_on_any_change(store):
    """A change in either score or grade adds a new point."""
    store.record_assessment("net", 72.0, "C")
    store.record_assessment("net", 71.0, "C")  # score moved
    store.record_assessment("net", 71.0, "B")  # grade moved
    assert _assessment_rows(store) == 3


def test_record_assessment_dedupe_emits_no_spurious_grade_event(store):
    """A deduped snapshot must not fire a grade_changed event either."""
    store.record_assessment("net", 72.0, "C")
    store.record_assessment("net", 72.0, "C")
    assert _events(store, "grade_changed") == []


# --- change events ---------------------------------------------------------


def _events(store, event_type=None):
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        if event_type:
            return conn.execute(
                "SELECT * FROM change_events WHERE event_type = ?", (event_type,)
            ).fetchall()
        return conn.execute("SELECT * FROM change_events").fetchall()


def test_first_port_scan_baseline_suppresses_port_events(store):
    """The baseline scan emits no per-port events (would otherwise flood)."""
    store.save_scan("port_scan", _port_scan())
    assert _events(store, "port_opened") == []
    assert _events(store, "port_closed") == []


def test_first_port_scan_emits_device_appeared(store):
    """A fresh install still shows discovered devices in history."""
    store.save_scan("port_scan", _port_scan())
    appeared = _events(store, "device_appeared")
    assert len(appeared) == 1
    assert json.loads(appeared[0]["detail"])["stable_key"] == "mac:00:11:22:33:44:55"


def test_second_scan_emits_port_opened(store):
    store.save_scan("port_scan", _port_scan())
    changed = _port_scan()
    changed.hosts[0].tcp.append(TcpPort(port=23, name="telnet"))
    store.save_scan("port_scan", changed)
    opened = _events(store, "port_opened")
    assert len(opened) == 1
    assert json.loads(opened[0]["detail"])["port"] == 23


def test_port_closed_event(store):
    store.save_scan("port_scan", _port_scan())
    closed_scan = _port_scan()
    closed_scan.hosts[0].tcp = []  # port 80 went away
    store.save_scan("port_scan", closed_scan)
    assert len(_events(store, "port_closed")) == 1


def test_dhcp_ip_change_is_not_material(store):
    """A device whose only change is its IP (MAC stable) emits no new events.

    The baseline still records its one device_appeared, but the IP-only rescan
    adds nothing material — no port churn, no second appearance/disappearance.
    """
    store.save_scan("port_scan", _port_scan())
    moved = _port_scan()
    moved.hosts[0].ip = "192.168.1.200"
    store.save_scan("port_scan", moved)
    assert _events(store, "port_opened") == []
    assert _events(store, "port_closed") == []
    assert _events(store, "device_disappeared") == []
    assert len(_events(store, "device_appeared")) == 1  # only the baseline's


def test_device_appeared_on_second_scan(store):
    store.save_scan("port_scan", _port_scan())  # baseline: first host appears
    bigger = _port_scan()
    bigger.hosts.append(Host(ip="192.168.1.50", mac="00:11:22:33:44:66", state="up"))
    store.save_scan("port_scan", bigger)
    keys = {json.loads(e["detail"])["stable_key"] for e in _events(store, "device_appeared")}
    assert "mac:00:11:22:33:44:66" in keys  # the newly-seen device
    assert keys == {"mac:00:11:22:33:44:55", "mac:00:11:22:33:44:66"}


def _cve_scan(cve_ids):
    return CveScanModel(
        target="192.168.1.0/24",
        results=[
            CveScanResultModel(
                ip="192.168.1.10",
                port=80,
                service="http",
                product="lighttpd",
                version="1.4",
                cves=[CveModel(id=c, description="x", severity="HIGH", score=7.5) for c in cve_ids],
            )
        ],
    )


def test_cve_appeared_event(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("cve_scan", _cve_scan(["CVE-2024-1"]))  # baseline
    store.save_scan("cve_scan", _cve_scan(["CVE-2024-1", "CVE-2024-2"]))
    appeared = _events(store, "cve_appeared")
    assert len(appeared) == 1
    assert json.loads(appeared[0]["detail"])["cve"] == "CVE-2024-2"


def test_grade_changed_event(store):
    store.record_assessment("192.168.1.0/24", 90, "A")  # baseline, no event
    store.record_assessment("192.168.1.0/24", 40, "D")
    events = _events(store, "grade_changed")
    assert len(events) == 1
    detail = json.loads(events[0]["detail"])
    assert detail["from"] == "A" and detail["to"] == "D"
    assert events[0]["host_id"] is None  # network-level event


# --- sql findings ----------------------------------------------------------


def _sql_scan(services: list[tuple[str, str]]) -> SqlScanModel:
    """Build a SQL scan from (service, status) pairs on the baseline host."""
    return SqlScanModel(
        id="s1",
        device_id="dev",
        version="1.0",
        results=[
            SqlScanResultModel(ip="192.168.1.10", port=3306, service=svc, status=status)
            for svc, status in services
        ],
        summary={},
    )


def test_save_sql_findings_linked_to_host(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("sql_scan", _sql_scan([("mysql", "successful")]))
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM findings WHERE kind = 'sql'").fetchone()
        assert row["ref"] == "mysql"
        assert row["severity"] == "CRITICAL"  # mysql weight 80 -> CRITICAL
        assert row["host_id"] is not None


def test_sql_finding_skips_non_vulnerable_status(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("sql_scan", _sql_scan([("mysql", "failed")]))
    with sqlite3.connect(store.db_path) as conn:
        rows = conn.execute("SELECT * FROM findings WHERE kind = 'sql'").fetchall()
        assert rows == []


def test_sql_vuln_appeared_event(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("sql_scan", _sql_scan([("mysql", "successful")]))  # baseline
    store.save_scan("sql_scan", _sql_scan([("mysql", "successful"), ("redis", "anonymous")]))
    appeared = _events(store, "sql_vuln_appeared")
    assert len(appeared) == 1
    assert json.loads(appeared[0]["detail"])["service"] == "redis"


def test_sql_vuln_resolved_event(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("sql_scan", _sql_scan([("mysql", "successful")]))  # baseline
    store.save_scan("sql_scan", _sql_scan([]))  # service secured
    assert len(_events(store, "sql_vuln_resolved")) == 1


# --- web findings ----------------------------------------------------------


def _web_result(**kwargs) -> WebScanResultModel:
    """A web result that is clean by default (CSP + HSTS present, no TLS issue)."""
    defaults = dict(
        ip="192.168.1.10",
        port=443,
        protocol="https",
        headers=SecurityHeadersModel(csp=True, hsts=True),
    )
    defaults.update(kwargs)
    return WebScanResultModel(**defaults)


def _web_scan(results: list[WebScanResultModel]) -> WebScanModel:
    return WebScanModel(id="w1", device_id="dev", version="1.0", results=results, summary={})


def test_save_web_findings_issue_kinds(store):
    store.save_scan("port_scan", _port_scan())
    res = _web_result(
        headers=SecurityHeadersModel(csp=False, hsts=False),
        tls=TlsInfoModel(expired=True),
        sensitive_files=[".env"],
    )
    store.save_scan("web_scan", _web_scan([res]))
    with sqlite3.connect(store.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT ref, severity FROM findings WHERE kind = 'web'").fetchall()
        by_ref = {r["ref"]: r["severity"] for r in rows}
        assert by_ref == {
            "expired_tls": "HIGH",  # 70
            "sensitive_file": "CRITICAL",  # 90
            "insecure_header": "MEDIUM",  # 40
        }


def test_clean_web_service_records_no_findings(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("web_scan", _web_scan([_web_result()]))
    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE kind = 'web'").fetchone()[0] == 0


def test_web_issue_appeared_event(store):
    store.save_scan("port_scan", _port_scan())
    store.save_scan("web_scan", _web_scan([_web_result()]))  # baseline, clean
    store.save_scan("web_scan", _web_scan([_web_result(sensitive_files=["backup.sql"])]))
    appeared = _events(store, "web_issue_appeared")
    assert len(appeared) == 1
    assert json.loads(appeared[0]["detail"])["issue"] == "sensitive_file"


# --- history views ---------------------------------------------------------


def test_recent_change_events_newest_first_with_host_context(store):
    store.save_scan("port_scan", _port_scan())
    changed = _port_scan()
    changed.hosts[0].tcp.append(TcpPort(port=23, name="telnet"))
    store.save_scan("port_scan", changed)

    events = store.recent_change_events()
    # Newest first: the port_opened from the rescan precedes the baseline's
    # device_appeared.
    assert [e["event_type"] for e in events] == ["port_opened", "device_appeared"]
    ev = events[0]
    assert ev["detail"]["port"] == 23
    assert ev["stable_key"] == "mac:00:11:22:33:44:55"


def test_recent_change_events_respects_limit(store):
    store.save_scan("port_scan", _port_scan())
    more = _port_scan()
    more.hosts[0].tcp.extend([TcpPort(port=p, name="x") for p in (23, 21, 8080)])
    store.save_scan("port_scan", more)
    assert len(store.recent_change_events(limit=2)) == 2


def test_score_trend_is_chronological(store):
    store.record_assessment("net", 90, "A")
    store.record_assessment("net", 70, "C")
    store.record_assessment("net", 50, "D")
    trend = store.score_trend()
    assert [t["score"] for t in trend] == [90, 70, 50]  # oldest -> newest
    assert [t["grade"] for t in trend] == ["A", "C", "D"]


def test_host_timeline_for_specific_host(store):
    store.save_scan("port_scan", _port_scan())
    changed = _port_scan()
    changed.hosts[0].tcp.append(TcpPort(port=23, name="telnet"))
    store.save_scan("port_scan", changed)
    timeline = store.host_timeline("mac:00:11:22:33:44:55")
    # Newest first: port_opened (rescan) then device_appeared (baseline).
    assert [e["event_type"] for e in timeline] == ["port_opened", "device_appeared"]


def test_history_views_empty_by_default(store):
    assert store.recent_change_events() == []
    assert store.score_trend() == []
    assert store.host_timeline("mac:00:11:22:33:44:55") == []


# --- report list + compare -------------------------------------------------


@pytest.fixture
def monotonic_now(monkeypatch):
    """Patch the store clock with strictly increasing ISO timestamps.

    Makes report-comparison window boundaries deterministic (real wall-clock
    calls microseconds apart could otherwise collide).
    """
    # Standard Library
    import itertools

    # First Party
    from edgewalker.core import sqlite_store as ss

    counter = itertools.count(1)
    monkeypatch.setattr(ss, "_now", lambda: f"2026-06-15T00:00:00.{next(counter):06d}+00:00")


def test_list_assessments_numbers_chronologically_newest_first(store, monotonic_now):
    store.record_assessment("net", 80, "B")
    store.record_assessment("net", 70, "C")
    store.record_assessment("net", 60, "D")
    items = store.list_assessments()
    assert [a["ordinal"] for a in items] == [3, 2, 1]  # stable ordinals, newest first
    assert [a["grade"] for a in items] == ["D", "C", "B"]
    assert store.list_assessments(limit=2) == items[:2]


def test_list_assessments_empty(store):
    assert store.list_assessments() == []


def test_compare_assessments_windows_changes(store, monotonic_now):
    store.save_scan("port_scan", _port_scan())  # baseline: device_appeared (before #1)
    store.record_assessment("net", 80, "B")  # report #1
    changed = _port_scan()
    changed.hosts[0].tcp.append(TcpPort(port=23, name="telnet"))
    store.save_scan("port_scan", changed)  # port_opened (between #1 and #2)
    store.record_assessment("net", 58, "D")  # report #2 (grade B->D at #2's instant)

    comp = store.compare_assessments(1, 2)
    assert comp["from"]["ordinal"] == 1 and comp["to"]["ordinal"] == 2
    assert comp["to"]["grade"] == "D"
    types = [c["event_type"] for c in comp["changes"]]
    assert "port_opened" in types
    assert "grade_changed" in types  # the to-report's own grade event is included
    assert "device_appeared" not in types  # baseline belongs before report #1


def test_compare_excludes_from_report_grade_event(store, monotonic_now):
    store.record_assessment("net", 80, "B")  # #1 (no grade event: first ever)
    store.record_assessment("net", 58, "D")  # #2 grade B->D
    store.record_assessment("net", 40, "F")  # #3 grade D->F

    comp = store.compare_assessments(2, 3)
    grade_events = [c for c in comp["changes"] if c["event_type"] == "grade_changed"]
    assert len(grade_events) == 1  # only #3's, not #2's (the from-boundary)
    assert grade_events[0]["detail"]["to"] == "F"


def test_compare_assessments_invalid_ordinal_raises(store, monotonic_now):
    store.record_assessment("net", 80, "B")
    with pytest.raises(ValueError):
        store.compare_assessments(1, 5)


def test_compare_assessments_requires_from_before_to(store, monotonic_now):
    store.record_assessment("net", 80, "B")
    store.record_assessment("net", 58, "D")
    with pytest.raises(ValueError):
        store.compare_assessments(2, 1)
