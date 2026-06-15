"""SQLite-backed result store for EdgeWalker scan history.

Implements the :class:`~edgewalker.core.result_store.ResultStore` interface on
top of stdlib ``sqlite3`` (no ORM). It records each scan's structured signal
into a small embedded database so repeated/scheduled scans build up per-device
history and a network score trend — without archiving every full scan payload
(we keep *current state* + a *change log*, per the plan's anti-bloat stance).

Connections are opened per operation (thread-safe with the TUI's worker
threads). The schema is created idempotently and versioned via
``PRAGMA user_version``.
"""

from __future__ import annotations

# Standard Library
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# First Party
from edgewalker.core.models import Base
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    scan_type     TEXT NOT NULL,
    target        TEXT NOT NULL,
    overall_score REAL,
    grade         TEXT,
    duration      REAL
);

CREATE TABLE IF NOT EXISTS hosts (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    stable_key             TEXT NOT NULL UNIQUE,
    first_seen             TEXT NOT NULL,
    last_seen              TEXT NOT NULL,
    label                  TEXT,
    device_type            TEXT,
    device_type_confidence REAL
);

CREATE TABLE IF NOT EXISTS host_state (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id),
    open_ports   TEXT,
    services     TEXT,
    fingerprint  TEXT,
    last_scan_id INTEGER REFERENCES scans(id),
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS change_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER REFERENCES hosts(id),
    scan_id    INTEGER REFERENCES scans(id),
    event_type TEXT NOT NULL,
    severity   TEXT,
    detail     TEXT,
    created_at TEXT NOT NULL,
    flushed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans(id),
    host_id    INTEGER REFERENCES hosts(id),
    kind       TEXT NOT NULL,
    severity   TEXT,
    ref        TEXT,
    detail     TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key  TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS score_history (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    date                 TEXT NOT NULL,
    granularity          TEXT NOT NULL,
    network_score        REAL,
    findings_by_severity TEXT,
    devices_added        INTEGER,
    devices_removed      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_change_events_host ON change_events(host_id, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target_time ON scans(target, started_at);
"""


def _now() -> str:
    """Current UTC time as an ISO-8601 string (the on-disk timestamp format)."""
    return datetime.now(timezone.utc).isoformat()


class SqliteResultStore:
    """Persist structured scan signal and history into a SQLite database."""

    def __init__(self, db_path: Path | str) -> None:
        """Open (creating if needed) the database at ``db_path`` and ensure schema."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._init_schema()

    # ------------------------------------------------------------- connection

    def _connect(self) -> sqlite3.Connection:
        """Open a fresh connection (one per operation; safe across threads)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        """Create tables idempotently and stamp the schema version."""
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------- ResultStore

    def save_scan(self, module: str, result: Base, *, keep_snapshot: bool = True) -> Path:
        """Persist a scan result's structured signal; return the DB path.

        Records a ``scans`` row for every module. For port scans it upserts
        ``hosts`` + ``host_state`` and writes per-port findings; for CVE and
        credential scans it writes the corresponding findings. (SQL/web findings
        are out of scope for the four diff signals and are not recorded here;
        their full payloads still land in the JSON store via the composite.)
        """
        with closing(self._connect()) as conn, conn:
            scan_id = self._insert_scan(conn, module, result)
            if module == "port_scan" and isinstance(result, PortScanModel):
                self._save_port_scan(conn, scan_id, result)
            elif module == "cve_scan":
                self._save_cve_findings(conn, scan_id, result)
            elif module == "password_scan":
                self._save_credential_findings(conn, scan_id, result)
        return self.db_path

    def get_latest_port_scan(self) -> PortScanModel | None:
        """Reconstruct the most recent port scan from stored host state."""
        with closing(self._connect()) as conn:
            scan = conn.execute(
                "SELECT id, target FROM scans WHERE scan_type = 'port_scan' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if scan is None:
                return None
            rows = conn.execute(
                "SELECT open_ports, fingerprint FROM host_state WHERE last_scan_id = ?",
                (scan["id"],),
            ).fetchall()
        hosts = [self._row_to_host(r) for r in rows]
        return PortScanModel(target=scan["target"], hosts=hosts, success=True)

    def record_assessment(self, target: str, score: float, grade: str) -> None:
        """Record a completed assessment's network score and grade as a scans row.

        This is what drives the score trend. Emitting a ``grade_changed``
        change-event from here is wired up alongside the diff engine.
        """
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO scans (started_at, finished_at, scan_type, target, "
                "overall_score, grade) VALUES (?, ?, 'assessment', ?, ?, ?)",
                (_now(), _now(), target, score, grade),
            )

    # ------------------------------------------------------------- write helpers

    def _insert_scan(self, conn: sqlite3.Connection, module: str, result: Base) -> int:
        """Insert a scans row for this module and return its id."""
        target = getattr(result, "target", "") or ""
        cur = conn.execute(
            "INSERT INTO scans (started_at, finished_at, scan_type, target) VALUES (?, ?, ?, ?)",
            (_now(), _now(), module, target),
        )
        return int(cur.lastrowid)

    def _upsert_host(self, conn: sqlite3.Connection, stable_key: str) -> int:
        """Insert or touch a host by stable_key; return its id."""
        now = _now()
        conn.execute(
            "INSERT OR IGNORE INTO hosts (stable_key, first_seen, last_seen) VALUES (?, ?, ?)",
            (stable_key, now, now),
        )
        conn.execute("UPDATE hosts SET last_seen = ? WHERE stable_key = ?", (now, stable_key))
        row = conn.execute("SELECT id FROM hosts WHERE stable_key = ?", (stable_key,)).fetchone()
        return int(row["id"])

    def _host_id_by_ip(self, conn: sqlite3.Connection, ip: str) -> Optional[int]:
        """Resolve a host id from a current IP recorded in host_state fingerprint."""
        rows = conn.execute("SELECT host_id, fingerprint FROM host_state").fetchall()
        for r in rows:
            fp = json.loads(r["fingerprint"]) if r["fingerprint"] else {}
            if fp.get("ip") == ip:
                return int(r["host_id"])
        return None

    def _save_port_scan(
        self, conn: sqlite3.Connection, scan_id: int, result: PortScanModel
    ) -> None:
        """Upsert host_state and per-port findings for each up host."""
        for host in (h for h in result.hosts if h.state == "up"):
            host_id = self._upsert_host(conn, host.stable_key)
            open_ports = [p.model_dump(mode="json") for p in host.tcp]
            fingerprint = {
                "ip": str(host.ip),
                "mac": host.mac,
                "hostname": host.hostname,
                "vendor": host.vendor,
                "state": host.state,
                "os": host.os,
                "mdns_name": host.mdns_name,
                "upnp_info": host.upnp_info,
                "http_server": host.http_server,
                "http_title": host.http_title,
            }
            conn.execute(
                "INSERT OR REPLACE INTO host_state "
                "(host_id, open_ports, services, fingerprint, last_scan_id, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    host_id,
                    json.dumps(open_ports),
                    json.dumps([p.name for p in host.tcp]),
                    json.dumps(fingerprint),
                    scan_id,
                    _now(),
                ),
            )
            for port in host.tcp:
                self._insert_finding(
                    conn,
                    scan_id,
                    host_id,
                    kind="port",
                    severity=None,
                    ref=str(port.port),
                    detail={"service": port.name, "product": port.product_name},
                )

    def _save_cve_findings(self, conn: sqlite3.Connection, scan_id: int, result: Base) -> None:
        """Write one finding per discovered CVE, linked to its host by IP."""
        for res in getattr(result, "results", []):
            host_id = self._host_id_by_ip(conn, str(res.ip))
            for cve in res.cves:
                self._insert_finding(
                    conn,
                    scan_id,
                    host_id,
                    kind="cve",
                    severity=cve.severity,
                    ref=cve.id,
                    detail={"product": res.product, "version": res.version, "score": cve.score},
                )

    def _save_credential_findings(
        self, conn: sqlite3.Connection, scan_id: int, result: Base
    ) -> None:
        """Write a finding for each successful (exposed) credential, linked by IP."""
        for res in getattr(result, "results", []):
            if str(res.login_attempt) not in ("successful", "StatusEnum.successful"):
                continue
            host_id = self._host_id_by_ip(conn, str(res.ip))
            self._insert_finding(
                conn,
                scan_id,
                host_id,
                kind="cred",
                severity="HIGH",
                ref=str(res.service),
                detail={"port": res.port},
            )

    def _insert_finding(
        self,
        conn: sqlite3.Connection,
        scan_id: int,
        host_id: Optional[int],
        *,
        kind: str,
        severity: Optional[str],
        ref: Optional[str],
        detail: Optional[dict],
    ) -> None:
        """Insert a single findings row."""
        conn.execute(
            "INSERT INTO findings (scan_id, host_id, kind, severity, ref, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, host_id, kind, severity, ref, json.dumps(detail) if detail else None, _now()),
        )

    # ------------------------------------------------------------- read helpers

    @staticmethod
    def _row_to_host(row: sqlite3.Row) -> Host:
        """Rebuild a Host model from a host_state row."""
        fp = json.loads(row["fingerprint"]) if row["fingerprint"] else {}
        ports = json.loads(row["open_ports"]) if row["open_ports"] else []
        return Host(
            ip=fp.get("ip"),
            mac=fp.get("mac", ""),
            hostname=fp.get("hostname", ""),
            vendor=fp.get("vendor", "Unknown"),
            state=fp.get("state", "up"),
            os=fp.get("os", []),
            tcp=[TcpPort(**p) for p in ports],
            mdns_name=fp.get("mdns_name"),
            upnp_info=fp.get("upnp_info"),
            http_server=fp.get("http_server"),
            http_title=fp.get("http_title"),
        )
