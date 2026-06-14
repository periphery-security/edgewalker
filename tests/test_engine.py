"""Tests for the headless Engine use-case layer (core/engine.py)."""

# Standard Library
import json
from unittest.mock import AsyncMock, MagicMock

# Third Party
import pytest

# First Party
from edgewalker.core.config import Settings
from edgewalker.core.engine import (
    ASSESSMENT_PLAN,
    AssessmentOptions,
    Engine,
    PhaseResult,
    Preflight,
)
from edgewalker.core.scanner_service import ScannerService
from edgewalker.modules.port_scan.models import Host, PortScanModel


def _port_model(hosts_up: int = 1) -> PortScanModel:
    """Build a minimal valid PortScanModel with ``hosts_up`` active hosts."""
    hosts = [
        Host(ip=f"127.0.0.{i + 1}", mac="00:00:00:00:00:00", state="up") for i in range(hosts_up)
    ]
    return PortScanModel(hosts=hosts, target="127.0.0.0/24")


# ----------------------------------------------------------------- AssessmentOptions


def test_effective_top_n_quick():
    assert AssessmentOptions().effective_top_n == 10


def test_effective_top_n_full_creds_means_all():
    assert AssessmentOptions(full_creds=True).effective_top_n is None


def test_effective_top_n_respects_explicit_value():
    assert AssessmentOptions(top_n=25).effective_top_n == 25


def test_runs_gating():
    opts = AssessmentOptions(run_sql=False, run_web=False)
    assert opts.runs("port")
    assert opts.runs("credential")
    assert opts.runs("cve")
    assert not opts.runs("sql")
    assert not opts.runs("web")
    assert not opts.runs("unknown")


# ----------------------------------------------------------------- preflight


def test_preflight_allow_override_short_circuits(monkeypatch):
    # Even if warnings/overrides exist, allow_override yields no blockers.
    monkeypatch.setattr(Settings, "get_security_warnings", lambda self: ["w"])
    monkeypatch.setattr("edgewalker.core.engine.get_active_overrides", lambda: {"EW_X": "env"})
    pf = Engine.preflight(AssessmentOptions(allow_override=True))
    assert isinstance(pf, Preflight)
    assert not pf.has_blockers


def test_preflight_collects_warnings_and_overrides(monkeypatch):
    monkeypatch.setattr(Settings, "get_security_warnings", lambda self: ["bad url"])
    monkeypatch.setattr(
        "edgewalker.core.engine.get_active_overrides",
        lambda: {"EW_API_URL": "environment variable", "EW_NVD": "environment variable"},
    )
    pf = Engine.preflight(AssessmentOptions())
    assert pf.has_blockers
    assert pf.warnings == ["bad url"]
    assert pf.override_sources == "environment variable"


def test_preflight_clean_has_no_blockers(monkeypatch):
    monkeypatch.setattr(Settings, "get_security_warnings", lambda self: [])
    monkeypatch.setattr("edgewalker.core.engine.get_active_overrides", lambda: {})
    pf = Engine.preflight(AssessmentOptions())
    assert not pf.has_blockers
    assert pf.override_sources == ""


# ----------------------------------------------------------------- run_assessment


def _engine_with_mock_scanner() -> tuple[Engine, MagicMock]:
    scanner = MagicMock(spec=ScannerService)
    scanner.perform_port_scan = AsyncMock(return_value=_port_model(1))
    scanner.perform_credential_scan = AsyncMock(return_value=MagicMock(name="cred"))
    scanner.perform_cve_scan = AsyncMock(return_value=MagicMock(name="cve"))
    scanner.perform_sql_scan = AsyncMock(return_value=MagicMock(name="sql"))
    scanner.perform_web_scan = AsyncMock(return_value=MagicMock(name="web"))
    return Engine(scanner), scanner


@pytest.mark.asyncio
async def test_run_assessment_full_sequence_in_order():
    engine, scanner = _engine_with_mock_scanner()
    phases = [p async for p in engine.run_assessment(AssessmentOptions(target="127.0.0.0/24"))]
    assert [p.module for p in phases] == list(ASSESSMENT_PLAN)
    assert all(not p.skipped for p in phases)
    scanner.perform_port_scan.assert_awaited_once()
    scanner.perform_credential_scan.assert_awaited_once()
    scanner.perform_web_scan.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_assessment_gates_disabled_modules():
    engine, scanner = _engine_with_mock_scanner()
    opts = AssessmentOptions(target="127.0.0.0/24", run_cves=False, run_sql=False)
    phases = {p.module: p async for p in engine.run_assessment(opts)}
    assert phases["cve"].skipped
    assert phases["sql"].skipped
    assert not phases["credential"].skipped
    scanner.perform_cve_scan.assert_not_called()
    scanner.perform_sql_scan.assert_not_called()
    scanner.perform_credential_scan.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_assessment_stops_when_no_hosts_up():
    engine, scanner = _engine_with_mock_scanner()
    scanner.perform_port_scan = AsyncMock(return_value=_port_model(0))
    phases = [p async for p in engine.run_assessment(AssessmentOptions(target="x"))]
    assert [p.module for p in phases] == ["port"]
    scanner.perform_credential_scan.assert_not_called()


@pytest.mark.asyncio
async def test_run_assessment_accepts_precomputed_port_results():
    engine, scanner = _engine_with_mock_scanner()
    pre = _port_model(1)
    phases = [
        p async for p in engine.run_assessment(AssessmentOptions(target="x"), port_results=pre)
    ]
    assert phases[0].result is pre
    scanner.perform_port_scan.assert_not_called()


@pytest.mark.asyncio
async def test_run_assessment_passes_effective_top_n_for_full_creds():
    engine, scanner = _engine_with_mock_scanner()
    opts = AssessmentOptions(target="x", full_creds=True)
    _ = [p async for p in engine.run_assessment(opts)]
    # full_creds -> top_n None ("all")
    _, kwargs = scanner.perform_credential_scan.call_args
    assert kwargs["top_n"] is None


# ----------------------------------------------------------------- progress passthrough


def test_progress_callback_proxies_to_scanner():
    scanner = MagicMock(spec=ScannerService)
    engine = Engine(scanner)
    cb = MagicMock()
    engine.progress_callback = cb
    assert scanner.progress_callback is cb
    assert engine.progress_callback is cb


# ----------------------------------------------------------------- load_report_inputs


def test_load_report_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr("edgewalker.core.engine.settings.output_dir", tmp_path)
    (tmp_path / "port_scan.json").write_text(json.dumps({"hosts": [1]}))
    (tmp_path / "cve_scan.json").write_text(json.dumps({"results": []}))

    inputs = Engine.load_report_inputs()
    assert inputs["port"] == {"hosts": [1]}
    assert inputs["cve"] == {"results": []}
    # Missing files map to empty dicts.
    assert inputs["cred"] == {}
    assert inputs["sql"] == {}
    assert inputs["web"] == {}


def test_phase_result_defaults():
    pr = PhaseResult("port")
    assert pr.module == "port"
    assert pr.result is None
    assert pr.skipped is False
