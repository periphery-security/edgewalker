"""EdgeWalker Engine — headless use-case layer (the "CLI-first" contract).

This module is the single, UI-agnostic entry point for running security
assessments. Every front-end (the Typer CLI and the Textual TUI) drives the
same ``Engine`` in-process, so the two stay at feature parity by construction
rather than by convention.

Hard rule: no Rich, no Textual, no ``console`` or ``logger`` output here.
The engine returns models and yields :class:`PhaseResult` objects; callers are
responsible for rendering them however suits their front-end.
"""

from __future__ import annotations

# Standard Library
import json
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, Optional

# Third Party
from pydantic import BaseModel

# First Party
from edgewalker.core.config import get_active_overrides, settings
from edgewalker.core.scanner_service import ScannerService
from edgewalker.modules.port_scan.models import PortScanModel

ProgressCallback = Callable[[str, str], None]

#: Canonical order in which assessment modules run. Both front-ends share this
#: so the sequence can never drift between the CLI and the TUI.
ASSESSMENT_PLAN: tuple[str, ...] = ("port", "credential", "cve", "sql", "web")


@dataclass(frozen=True)
class AssessmentOptions:
    """Render-agnostic options describing a single assessment run."""

    target: Optional[str] = None
    full_scan: bool = False
    full_creds: bool = False
    run_creds: bool = True
    run_cves: bool = True
    run_sql: bool = True
    run_web: bool = True
    unprivileged: bool = False
    verbose: bool = False
    top_n: Optional[int] = 10
    allow_override: bool = False

    @property
    def effective_top_n(self) -> Optional[int]:
        """Credentials to test per service (``None`` means "all")."""
        return None if self.full_creds else self.top_n

    def runs(self, module: str) -> bool:
        """Return whether ``module`` is enabled for this run."""
        return {
            "port": True,
            "credential": self.run_creds,
            "cve": self.run_cves,
            "sql": self.run_sql,
            "web": self.run_web,
        }.get(module, False)


@dataclass
class PhaseResult:
    """The outcome of one module within an assessment sequence."""

    module: str
    result: Optional[BaseModel] = None
    skipped: bool = False


@dataclass
class Preflight:
    """Render-agnostic result of the pre-scan safety check.

    Holds the *data* a front-end needs to decide whether to warn the user and
    ask for confirmation. The decision of *how* to present it (Rich prompt vs.
    Textual modal) stays with the caller.
    """

    warnings: list[str] = field(default_factory=list)
    overrides: dict[str, str] = field(default_factory=dict)

    @property
    def has_blockers(self) -> bool:
        """True if anything warrants a confirmation prompt."""
        return bool(self.warnings or self.overrides)

    @property
    def override_sources(self) -> str:
        """Comma-separated, de-duplicated override sources for display."""
        return ", ".join(sorted(set(self.overrides.values())))


class Engine:
    """Headless orchestration over :class:`ScannerService`.

    Composes the lower-level scanner/persistence/telemetry service and exposes
    one canonical assessment sequence plus per-module entry points.
    """

    def __init__(self, scanner: Optional[ScannerService] = None) -> None:
        """Initialize the engine.

        Args:
            scanner: Optional pre-built scanner service (lets a front-end share
                a single service instance with its telemetry callbacks wired up).
        """
        self.scanner = scanner or ScannerService()

    @property
    def progress_callback(self) -> Optional[ProgressCallback]:
        """The scanner's live progress callback (events flow straight through)."""
        return self.scanner.progress_callback

    @progress_callback.setter
    def progress_callback(self, callback: Optional[ProgressCallback]) -> None:
        self.scanner.progress_callback = callback

    # ------------------------------------------------------------------ preflight

    @staticmethod
    def preflight(opts: AssessmentOptions) -> Preflight:
        """Compute the pre-scan safety check shared by every front-end.

        Returns an empty :class:`Preflight` (no blockers) when the caller has
        explicitly opted out via ``allow_override``.
        """
        if opts.allow_override:
            return Preflight()
        return Preflight(
            warnings=settings.get_security_warnings(),
            overrides=get_active_overrides(),
        )

    # ------------------------------------------------------------- single modules

    async def run_port_scan(self, opts: AssessmentOptions) -> PortScanModel:
        """Run the port scan for ``opts``."""
        return await self.scanner.perform_port_scan(
            target=opts.target,
            full=opts.full_scan,
            unprivileged=opts.unprivileged,
            verbose=opts.verbose,
        )

    async def run_credential_scan(
        self, opts: AssessmentOptions, port_results: Optional[PortScanModel] = None
    ) -> BaseModel:
        """Run the credential scan against prior port results."""
        return await self.scanner.perform_credential_scan(
            port_results=port_results, top_n=opts.effective_top_n
        )

    async def run_cve_scan(
        self, opts: AssessmentOptions, port_results: Optional[PortScanModel] = None
    ) -> BaseModel:
        """Run the CVE scan against prior port results."""
        return await self.scanner.perform_cve_scan(port_results=port_results)

    async def run_sql_scan(
        self, opts: AssessmentOptions, port_results: Optional[PortScanModel] = None
    ) -> BaseModel:
        """Run the SQL audit against prior port results."""
        return await self.scanner.perform_sql_scan(
            port_results=port_results, top_n=opts.effective_top_n, verbose=opts.verbose
        )

    async def run_web_scan(
        self, opts: AssessmentOptions, port_results: Optional[PortScanModel] = None
    ) -> BaseModel:
        """Run the web audit against prior port results."""
        return await self.scanner.perform_web_scan(port_results=port_results, verbose=opts.verbose)

    # ------------------------------------------------------------- full sequence

    async def run_assessment(
        self,
        opts: AssessmentOptions,
        *,
        port_results: Optional[PortScanModel] = None,
    ) -> AsyncIterator[PhaseResult]:
        """Run the canonical assessment sequence, yielding one result per module.

        Yields each :class:`PhaseResult` as soon as it completes so callers can
        render incrementally. A port scan always runs first (unless results are
        supplied); if no hosts are up the sequence stops after the port phase,
        mirroring the previous behaviour of both front-ends.

        Args:
            opts: The assessment options (target, depth, which modules to run).
            port_results: Optional pre-computed port results to start from.

        Yields:
            One :class:`PhaseResult` per module in :data:`ASSESSMENT_PLAN`.
        """
        if port_results is None:
            port_results = await self.run_port_scan(opts)
        yield PhaseResult("port", port_results)

        hosts_up = [h for h in port_results.hosts if h.state == "up"]
        if not hosts_up:
            return

        runners = {
            "credential": self.run_credential_scan,
            "cve": self.run_cve_scan,
            "sql": self.run_sql_scan,
            "web": self.run_web_scan,
        }
        for module in ASSESSMENT_PLAN[1:]:
            if not opts.runs(module):
                yield PhaseResult(module, skipped=True)
                continue
            result = await runners[module](opts, port_results)
            yield PhaseResult(module, result)

    # ------------------------------------------------------------- report inputs

    @staticmethod
    def load_report_inputs() -> dict[str, dict]:
        """Load the latest persisted ``*_scan.json`` bundle for report assembly.

        Returns a dict with keys ``port``, ``cred``, ``cve``, ``sql``, ``web``;
        missing files yield an empty dict for that key. Centralizes the loading
        that both front-ends previously open-coded for every report and topology
        view.
        """
        files = {
            "port": "port_scan.json",
            "cred": "password_scan.json",
            "cve": "cve_scan.json",
            "sql": "sql_scan.json",
            "web": "web_scan.json",
        }
        inputs: dict[str, dict] = {}
        for key, filename in files.items():
            path = settings.output_dir / filename
            if path.exists():
                with open(path) as f:
                    inputs[key] = json.load(f)
            else:
                inputs[key] = {}
        return inputs
