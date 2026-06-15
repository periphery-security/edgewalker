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
