# Standard Library
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
