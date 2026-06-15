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
    diff_sql,
    diff_web,
)
from edgewalker.core.models import Base
from edgewalker.core.risk import RiskEngine
from edgewalker.modules.port_scan.models import Host, PortScanModel, TcpPort
from edgewalker.modules.sql_scan.models import SQL_VULNERABLE_STATUSES

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
        ``hosts`` + ``host_state`` and writes per-port findings; for CVE,
        credential, SQL and web scans it writes the corresponding findings and
        emits the matching change events. Full scan payloads still land in the
        JSON store via the composite.
        """
        with closing(self._connect()) as conn, conn:
            scan_id = self._insert_scan(conn, module, result)
            if module == "port_scan" and isinstance(result, PortScanModel):
                self._save_port_scan(conn, scan_id, result)
            elif module == "cve_scan":
                self._save_cve_findings(conn, scan_id, result)
            elif module == "password_scan":
                self._save_credential_findings(conn, scan_id, result)
            elif module == "sql_scan":
                self._save_sql_findings(conn, scan_id, result)
            elif module == "web_scan":
                self._save_web_findings(conn, scan_id, result)
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

        Idempotent against churn: a snapshot whose score *and* grade match the
        most recent assessment is dropped. This lets front-ends call this freely
        from every report/overview convergence point (TUI run-all terminus, CLI
        report view, the guided sequence) without flooding the trend with
        duplicate points — only genuine score movement adds a row.
        """
        with closing(self._connect()) as conn, conn:
            prior = conn.execute(
                "SELECT overall_score, grade FROM scans WHERE scan_type = 'assessment' "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if prior is not None and prior["grade"] == grade and prior["overall_score"] == score:
                return  # collapse consecutive identical points
            now = _now()
            cur = conn.execute(
                "INSERT INTO scans (started_at, finished_at, scan_type, target, "
                "overall_score, grade) VALUES (?, ?, 'assessment', ?, ?, ?)",
                (now, now, target, score, grade),
            )
            scan_id = int(cur.lastrowid)
            # Stamp the grade event at the assessment's own instant so report
            # comparisons can window cleanly on assessment timestamps.
            for ev in diff_grade(prior["grade"] if prior else None, grade):
                self._record_event(conn, scan_id, None, ev, created_at=now)

    # ------------------------------------------------------------- history views

    @staticmethod
    def _event_rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
        """Map change_event rows joined to host context into plain dicts."""
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

    def recent_change_events(self, limit: int = 20) -> list[dict]:
        """Return the most recent change events (newest first), with host context."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT ce.created_at, ce.event_type, ce.severity, ce.detail, "
                "h.stable_key, h.label FROM change_events ce "
                "LEFT JOIN hosts h ON h.id = ce.host_id ORDER BY ce.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return self._event_rows_to_dicts(rows)

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

    def list_assessments(self, limit: Optional[int] = None) -> list[dict]:
        """Return recorded assessments newest-first, each with a chronological ordinal.

        The ordinal is 1-based and stable (``#1`` is the first-ever assessment),
        so it can be used to refer to a report in :meth:`compare_assessments`.
        ``limit`` caps how many of the most recent reports are returned.
        """
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, started_at, overall_score, grade, target FROM scans "
                "WHERE scan_type = 'assessment' AND overall_score IS NOT NULL ORDER BY id ASC"
            ).fetchall()
        items = [
            {
                "ordinal": i + 1,
                "id": r["id"],
                "at": r["started_at"],
                "score": r["overall_score"],
                "grade": r["grade"],
                "target": r["target"],
            }
            for i, r in enumerate(rows)
        ]
        items.reverse()  # newest first for display
        return items[:limit] if limit is not None else items

    def compare_assessments(self, from_ordinal: int, to_ordinal: int) -> dict:
        """Compare two recorded assessments by their chronological ordinal.

        Returns ``{"from": meta, "to": meta, "changes": [...]}`` where ``changes``
        are the material change events recorded after the ``from`` assessment up
        to and including the ``to`` assessment (newest first). Raises
        ``ValueError`` if an ordinal is out of range or ``from`` is not older
        than ``to``.
        """
        by_ordinal = {a["ordinal"]: a for a in self.list_assessments()}
        if from_ordinal not in by_ordinal or to_ordinal not in by_ordinal:
            raise ValueError(f"report numbers must be in 1..{len(by_ordinal)}")
        if from_ordinal >= to_ordinal:
            raise ValueError("the 'from' report must be older than the 'to' report")
        a_from, a_to = by_ordinal[from_ordinal], by_ordinal[to_ordinal]
        return {
            "from": a_from,
            "to": a_to,
            "changes": self._changes_between(a_from["at"], a_to["at"]),
        }

    def _changes_between(self, start_at: str, end_at: str) -> list[dict]:
        """Return change events with created_at in ``(start_at, end_at]``, newest first."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT ce.created_at, ce.event_type, ce.severity, ce.detail, "
                "h.stable_key, h.label FROM change_events ce "
                "LEFT JOIN hosts h ON h.id = ce.host_id "
                "WHERE ce.created_at > ? AND ce.created_at <= ? ORDER BY ce.id DESC",
                (start_at, end_at),
            ).fetchall()
        return self._event_rows_to_dicts(rows)

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

    @staticmethod
    def _ip_to_host_id_map(conn: sqlite3.Connection) -> dict[str, int]:
        """Build an IP -> host_id map in one pass (the IP lives in fingerprint JSON).

        Findings link to hosts by IP; computing this map once per scan turns the
        per-finding lookup from a full host_state scan + JSON parse (O(hosts) each,
        O(hosts x findings) overall) into an O(1) dict lookup.
        """
        mapping: dict[str, int] = {}
        for r in conn.execute("SELECT host_id, fingerprint FROM host_state").fetchall():
            fp = json.loads(r["fingerprint"]) if r["fingerprint"] else {}
            ip = fp.get("ip")
            if ip is not None:
                mapping.setdefault(str(ip), int(r["host_id"]))
        return mapping

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
        self,
        conn: sqlite3.Connection,
        scan_id: int,
        host_id: Optional[int],
        event: ChangeEvent,
        created_at: Optional[str] = None,
    ) -> None:
        """Persist a single change event (flushed_at stays NULL until Phase 4).

        ``created_at`` defaults to now; callers pass an explicit timestamp when
        an event must share an instant with its scan row (e.g. an assessment's
        ``grade_changed``, so report-comparison windows are unambiguous).
        """
        conn.execute(
            "INSERT INTO change_events "
            "(host_id, scan_id, event_type, severity, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                host_id,
                scan_id,
                event.event_type,
                event.severity,
                json.dumps(event.detail),
                created_at or _now(),
            ),
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

        The first-ever port scan establishes a baseline: per-port diffs are
        suppressed (every open port would otherwise look "new", flooding the
        log), but each discovered device still emits a ``device_appeared`` event
        — bounded at one per host — so a fresh install shows something in
        history. Subsequent scans diff against the immediately prior port scan.
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

        # Device appearance/disappearance is diffed even on the baseline scan
        # (prior_ports is empty -> every discovered host is "appeared"), unlike
        # the per-port diff above which stays silent on the baseline.
        for ev in diff_devices(set(prior_ports), new_keys):
            host_id = self._host_id_by_key(conn, ev.detail["stable_key"])
            self._record_event(conn, scan_id, host_id, ev)

    def _save_cve_findings(self, conn: sqlite3.Connection, scan_id: int, result: Base) -> None:
        """Write CVE findings (linked to host by IP) and emit cve change events."""
        prior_scan_id = self._prior_scan_id(conn, "cve_scan", scan_id)
        prior = self._refs_by_host_for_scan(conn, prior_scan_id, "cve")
        ip_map = self._ip_to_host_id_map(conn)
        new: dict[Optional[int], dict[str, str]] = {}

        for res in getattr(result, "results", []):
            host_id = ip_map.get(str(res.ip))
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
        ip_map = self._ip_to_host_id_map(conn)
        new: dict[Optional[int], set[str]] = {}

        for res in getattr(result, "results", []):
            if str(res.login_attempt) not in ("successful", "StatusEnum.successful"):
                continue
            host_id = ip_map.get(str(res.ip))
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

    def _save_sql_findings(self, conn: sqlite3.Connection, scan_id: int, result: Base) -> None:
        """Write SQL findings (linked to host by IP) and emit sql change events.

        A finding is recorded for each service whose login succeeded or allowed
        anonymous access (mirroring the risk engine); severity comes from the
        configured ``sql_severity`` weights.
        """
        prior_scan_id = self._prior_scan_id(conn, "sql_scan", scan_id)
        prior = self._refs_by_host_for_scan(conn, prior_scan_id, "sql")
        ip_map = self._ip_to_host_id_map(conn)
        new: dict[Optional[int], dict[str, str]] = {}

        for res in getattr(result, "results", []):
            status = getattr(res.status, "value", str(res.status))
            if status not in SQL_VULNERABLE_STATUSES:
                continue
            svc = getattr(res.service, "value", str(res.service))
            severity = self._severity_of_sql(svc)
            host_id = ip_map.get(str(res.ip))
            new.setdefault(host_id, {})[svc] = severity
            self._insert_finding(
                conn,
                scan_id,
                host_id,
                kind="sql",
                severity=severity,
                ref=svc,
                detail={"port": res.port, "status": status, "version": res.version},
            )

        if prior_scan_id is not None:
            for host_id in set(prior) | set(new):
                old_services = {ref for ref, _ in prior.get(host_id, [])}
                for ev in diff_sql(old_services, new.get(host_id, {})):
                    self._record_event(conn, scan_id, host_id, ev)

    def _save_web_findings(self, conn: sqlite3.Connection, scan_id: int, result: Base) -> None:
        """Write web findings (linked to host by IP) and emit web change events.

        Each web service contributes up to three issue kinds — ``sensitive_file``,
        ``expired_tls`` and ``insecure_header`` — with severity from the
        configured ``web_severity`` weights.
        """
        prior_scan_id = self._prior_scan_id(conn, "web_scan", scan_id)
        prior = self._refs_by_host_for_scan(conn, prior_scan_id, "web")
        ip_map = self._ip_to_host_id_map(conn)
        new: dict[Optional[int], dict[str, str]] = {}

        for res in getattr(result, "results", []):
            host_id = ip_map.get(str(res.ip))
            for issue, severity in self._web_issues(res).items():
                new.setdefault(host_id, {})[issue] = severity
                self._insert_finding(
                    conn,
                    scan_id,
                    host_id,
                    kind="web",
                    severity=severity,
                    ref=issue,
                    detail={"port": res.port},
                )

        if prior_scan_id is not None:
            for host_id in set(prior) | set(new):
                old_issues = {ref for ref, _ in prior.get(host_id, [])}
                for ev in diff_web(old_issues, new.get(host_id, {})):
                    self._record_event(conn, scan_id, host_id, ev)

    @staticmethod
    def _severity_of_sql(service: str) -> str:
        """Severity label for a vulnerable SQL service via the risk weights."""
        score = settings.sql_severity.get(service, settings.sql_severity_default)
        return RiskEngine.get_risk_level(score)[0]

    @staticmethod
    def _web_issues(res: object) -> dict[str, str]:
        """Map a web result to its issue kinds and severity labels.

        Mirrors :meth:`RiskEngine._calculate_web_score`: an expired certificate,
        any exposed sensitive file, and a missing CSP/HSTS header each surface as
        a distinct issue keyed by kind.
        """
        issues: dict[str, str] = {}
        tls = getattr(res, "tls", None)
        if tls is not None and getattr(tls, "expired", False):
            score = settings.web_severity.get("expired_cert", 70)
            issues["expired_tls"] = RiskEngine.get_risk_level(score)[0]
        if getattr(res, "sensitive_files", None):
            score = settings.web_severity.get("sensitive_file", 90)
            issues["sensitive_file"] = RiskEngine.get_risk_level(score)[0]
        headers = getattr(res, "headers", None)
        if headers is not None and (
            not getattr(headers, "csp", False) or not getattr(headers, "hsts", False)
        ):
            score = settings.web_severity.get("missing_headers", 40)
            issues["insecure_header"] = RiskEngine.get_risk_level(score)[0]
        return issues

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
