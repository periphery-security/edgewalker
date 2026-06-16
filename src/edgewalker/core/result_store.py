"""Result persistence abstraction for EdgeWalker.

The scan engine returns Pydantic models and should not care whether results
land in JSON files (the one-off CLI/TUI path) or, later, a database (the
always-on service daemon). ``ResultStore`` is that seam: ``ScannerService``
writes each scan and reads back the latest port scan *through the store*, so
swapping persistence becomes a constructor argument rather than a rewrite.

Phase 1 ships only :class:`JsonResultStore`, which preserves today's
file-based behaviour exactly. A ``SqliteResultStore`` carrying diffing,
change-events, and retention arrives with the continuous-monitoring phases;
the protocol will grow the methods it needs at that point.
"""

from __future__ import annotations

# Standard Library
import json
from pathlib import Path
from typing import Protocol, runtime_checkable

# First Party
from edgewalker.core.models import Base
from edgewalker.modules.port_scan.models import PortScanModel
from edgewalker.utils import get_output_dir, save_results


@runtime_checkable
class ResultStore(Protocol):
    """Where scan results are persisted and read back from."""

    def save_scan(self, module: str, result: Base, *, keep_snapshot: bool = True) -> Path:
        """Persist a scan result for ``module`` and return its canonical path.

        Args:
            module: Scan module slug (e.g. ``"port_scan"``).
            result: The scan result model to persist.
            keep_snapshot: When True, also retain a per-device snapshot
                alongside the canonical "latest" artifact.
        """
        ...

    def get_latest_port_scan(self) -> PortScanModel | None:
        """Return the most recent port scan, or None if none has been stored."""
        ...

    def record_assessment(self, target: str, score: float, grade: str) -> None:
        """Record a completed assessment's network score and grade.

        History-tracking stores persist a score-trend point and may emit a
        grade-change event; the one-off JSON store is free to no-op.
        """
        ...


class JsonResultStore:
    """One-off file store mirroring the original ``save_results`` behaviour.

    Always writes the canonical ``{module}.json`` (what the CLI, TUI, and
    report layers read), and by default also writes a per-device
    ``{module}_{device_id}.json`` snapshot, matching the pre-store layout.
    """

    def save_scan(self, module: str, result: Base, *, keep_snapshot: bool = True) -> Path:
        """Write the scan result to JSON and return the canonical "latest" path."""
        data = result.model_dump(mode="json")
        if keep_snapshot:
            save_results(data, f"{module}_{result.device_id}.json")
        return save_results(data, f"{module}.json")

    def get_latest_port_scan(self) -> PortScanModel | None:
        """Load the latest ``port_scan.json``, or None if it does not exist."""
        path = get_output_dir() / "port_scan.json"
        if not path.exists():
            return None
        with open(path) as f:
            return PortScanModel(**json.load(f))

    def record_assessment(self, target: str, score: float, grade: str) -> None:
        """No-op: the one-off JSON store does not track assessment history."""


class CompositeStore:
    """Fan-out store: writes to every backing store, reads from the primary.

    The first store is the primary — its ``get_latest_port_scan`` is
    authoritative and its ``save_scan`` return value (the portable JSON path)
    is what callers get back. Additional stores receive the same writes for
    history/secondary purposes. Used to dual-write the one-off CLI path to both
    the JSON files (portable, what existing readers consume) and the SQLite
    history database.
    """

    def __init__(self, primary: ResultStore, *others: ResultStore) -> None:
        """Compose ``primary`` (authoritative for reads) with extra write targets."""
        self.stores: tuple[ResultStore, ...] = (primary, *others)

    @property
    def primary(self) -> ResultStore:
        """The authoritative store used for reads and the canonical save path."""
        return self.stores[0]

    def save_scan(self, module: str, result: Base, *, keep_snapshot: bool = True) -> Path:
        """Write to every store; return the primary's (portable) path."""
        path = self.primary.save_scan(module, result, keep_snapshot=keep_snapshot)
        for store in self.stores[1:]:
            store.save_scan(module, result, keep_snapshot=keep_snapshot)
        return path

    def get_latest_port_scan(self) -> PortScanModel | None:
        """Read the latest port scan from the primary store."""
        return self.primary.get_latest_port_scan()

    def record_assessment(self, target: str, score: float, grade: str) -> None:
        """Record the assessment in every store (the JSON store no-ops)."""
        for store in self.stores:
            store.record_assessment(target, score, grade)
