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
from edgewalker.core.config import settings
from edgewalker.core.diff import (
    ChangeEvent,
    diff_credentials,
    diff_cves,
    diff_devices,
    diff_grade,
    diff_ports,
)
from edgewalker.core.models import Base
from edgewalker.core.risk import RiskEngine
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
        """Record a completed assessment's score/grade and emit any grade change.

        Drives the score trend; fires a ``grade_changed`` event (network-level,
        host_id NULL) when the grade differs from the previous assessment.
        """
        with closing(self._connect()) as conn, conn:
            prior = conn.execute(
                "SELECT grade FROM scans WHERE scan_type = 'assessment' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            cur = conn.execute(
                "INSERT INTO scans (started_at, finished_at, scan_type, target, "
                "overall_score, grade) VALUES (?, ?, 'assessment', ?, ?, ?)",
                (_now(), _now(), target, score, grade),
            )
            scan_id = int(cur.lastrowid)
            for ev in diff_grade(prior["grade"] if prior else None, grade):
                self._record_event(conn, scan_id, None, ev)

    # ------------------------------------------------------------- history views

    def recent_change_events(self, limit: int = 20) -> list[dict]:
        """Return the most recent change events (newest first), with host context."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT ce.created_at, ce.event_type, ce.severity, ce.detail, "
                "h.stable_key, h.label FROM change_events ce "
                "LEFT JOIN hosts h ON h.id = ce.host_id ORDER BY ce.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "created_at": r["created_at"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "detail": json.loads(r["detail"]) if r["detail"] else {},
                "stable_key": r["stable_key"],
                "label": r["label"],
            }
            for r in rows
        ]

    def score_trend(self, limit: int = 30) -> list[dict]:
        """Return recent assessment scores oldest-first (for a trend/sparkline)."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT started_at, overall_score, grade FROM scans "
                "WHERE scan_type = 'assessment' AND overall_score IS NOT NULL "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        trend = [
            {"at": r["started_at"], "score": r["overall_score"], "grade": r["grade"]} for r in rows
        ]
        trend.reverse()  # chronological for plotting
        return trend

    def host_timeline(self, stable_key: str, limit: int = 20) -> list[dict]:
        """Return the change-event history for a single host (newest first)."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT ce.created_at, ce.event_type, ce.severity, ce.detail "
                "FROM change_events ce JOIN hosts h ON h.id = ce.host_id "
                "WHERE h.stable_key = ? ORDER BY ce.id DESC LIMIT ?",
                (stable_key, limit),
            ).fetchall()
        return [
            {
                "created_at": r["created_at"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "detail": json.loads(r["detail"]) if r["detail"] else {},
            }
            for r in rows
        ]

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

    def _host_id_by_key(self, conn: sqlite3.Connection, stable_key: str) -> Optional[int]:
        """Resolve a host id from its stable_key."""
        row = conn.execute("SELECT id FROM hosts WHERE stable_key = ?", (stable_key,)).fetchone()
        return int(row["id"]) if row else None

    @staticmethod
    def _prior_scan_id(conn: sqlite3.Connection, scan_type: str, before_id: int) -> Optional[int]:
        """Return the id of the most recent scan of ``scan_type`` before ``before_id``."""
        row = conn.execute(
            "SELECT MAX(id) AS id FROM scans WHERE scan_type = ? AND id < ?",
            (scan_type, before_id),
        ).fetchone()
        return int(row["id"]) if row and row["id"] is not None else None

    @staticmethod
    def _ports_by_key_for_scan(
        conn: sqlite3.Connection, scan_id: Optional[int]
    ) -> dict[str, set[int]]:
        """Map stable_key -> set of open ports recorded by the given scan."""
        if scan_id is None:
            return {}
        rows = conn.execute(
            "SELECT h.stable_key AS key, hs.open_ports AS ports FROM host_state hs "
            "JOIN hosts h ON h.id = hs.host_id WHERE hs.last_scan_id = ?",
            (scan_id,),
        ).fetchall()
        result: dict[str, set[int]] = {}
        for r in rows:
            ports = {p["port"] for p in json.loads(r["ports"])} if r["ports"] else set()
            result[r["key"]] = ports
        return result

    @staticmethod
    def _refs_by_host_for_scan(
        conn: sqlite3.Connection, scan_id: Optional[int], kind: str
    ) -> dict[Optional[int], list[tuple[str, Optional[str]]]]:
        """Map host_id -> [(ref, severity), ...] for findings of ``kind`` in a scan."""
        result: dict[Optional[int], list[tuple[str, Optional[str]]]] = {}
        if scan_id is None:
            return result
        rows = conn.execute(
            "SELECT host_id, ref, severity FROM findings WHERE scan_id = ? AND kind = ?",
            (scan_id, kind),
        ).fetchall()
        for r in rows:
            result.setdefault(r["host_id"], []).append((r["ref"], r["severity"]))
        return result

    def _record_event(
        self, conn: sqlite3.Connection, scan_id: int, host_id: Optional[int], event: ChangeEvent
    ) -> None:
        """Persist a single change event (flushed_at stays NULL until Phase 4)."""
        conn.execute(
            "INSERT INTO change_events "
            "(host_id, scan_id, event_type, severity, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (host_id, scan_id, event.event_type, event.severity, json.dumps(event.detail), _now()),
        )

    @staticmethod
    def _severity_of_port(port: int) -> str:
        """Map a port to a severity label via the configured risk weights."""
        score = settings.port_severity.get(port, settings.port_severity_default)
        return RiskEngine.get_risk_level(score)[0]

    def _save_port_scan(
        self, conn: sqlite3.Connection, scan_id: int, result: PortScanModel
    ) -> None:
        """Upsert host_state + per-port findings and emit port/device change events.

        The first-ever port scan establishes a baseline and emits no events
        (everything would otherwise look "new"); subsequent scans diff against
        the immediately prior port scan.
        """
        prior_scan_id = self._prior_scan_id(conn, "port_scan", scan_id)
        prior_ports = self._ports_by_key_for_scan(conn, prior_scan_id)
        new_keys: set[str] = set()

        for host in (h for h in result.hosts if h.state == "up"):
            host_id = self._upsert_host(conn, host.stable_key)
            new_keys.add(host.stable_key)
            new_ports = {p.port for p in host.tcp}
            if prior_scan_id is not None:
                for ev in diff_ports(
                    prior_ports.get(host.stable_key, set()), new_ports, self._severity_of_port
                ):
                    self._record_event(conn, scan_id, host_id, ev)
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

        if prior_scan_id is not None:
            for ev in diff_devices(set(prior_ports), new_keys):
                host_id = self._host_id_by_key(conn, ev.detail["stable_key"])
                self._record_event(conn, scan_id, host_id, ev)

    def _save_cve_findings(self, conn: sqlite3.Connection, scan_id: int, result: Base) -> None:
        """Write CVE findings (linked to host by IP) and emit cve change events."""
        prior_scan_id = self._prior_scan_id(conn, "cve_scan", scan_id)
        prior = self._refs_by_host_for_scan(conn, prior_scan_id, "cve")
        new: dict[Optional[int], dict[str, str]] = {}

        for res in getattr(result, "results", []):
            host_id = self._host_id_by_ip(conn, str(res.ip))
            for cve in res.cves:
                new.setdefault(host_id, {})[cve.id] = cve.severity
                self._insert_finding(
                    conn,
                    scan_id,
                    host_id,
                    kind="cve",
                    severity=cve.severity,
                    ref=cve.id,
                    detail={"product": res.product, "version": res.version, "score": cve.score},
                )

        if prior_scan_id is not None:
            for host_id in set(prior) | set(new):
                old_ids = {ref for ref, _ in prior.get(host_id, [])}
                for ev in diff_cves(old_ids, new.get(host_id, {})):
                    self._record_event(conn, scan_id, host_id, ev)

    def _save_credential_findings(
        self, conn: sqlite3.Connection, scan_id: int, result: Base
    ) -> None:
        """Write exposed-credential findings (by IP) and emit credential change events."""
        prior_scan_id = self._prior_scan_id(conn, "password_scan", scan_id)
        prior = self._refs_by_host_for_scan(conn, prior_scan_id, "cred")
        new: dict[Optional[int], set[str]] = {}

        for res in getattr(result, "results", []):
            if str(res.login_attempt) not in ("successful", "StatusEnum.successful"):
                continue
            host_id = self._host_id_by_ip(conn, str(res.ip))
            new.setdefault(host_id, set()).add(str(res.service))
            self._insert_finding(
                conn,
                scan_id,
                host_id,
                kind="cred",
                severity="HIGH",
                ref=str(res.service),
                detail={"port": res.port},
            )

        if prior_scan_id is not None:
            for host_id in set(prior) | set(new):
                old_services = {ref for ref, _ in prior.get(host_id, [])}
                for ev in diff_credentials(old_services, new.get(host_id, set())):
                    self._record_event(conn, scan_id, host_id, ev)

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
