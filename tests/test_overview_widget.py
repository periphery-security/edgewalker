"""Tests for the dashboard overview renderables (tui/widgets/overview.py)."""

# Third Party
from rich.console import Console

# First Party
from edgewalker.core.findings import AssessmentSummary, DeviceRow, Finding
from edgewalker.tui.widgets import overview


def _render(renderable) -> str:
    """Render to plain text for content assertions."""
    console = Console(width=100, file=None, record=True)
    console.print(renderable)
    return console.export_text()


def _summary() -> AssessmentSummary:
    return AssessmentSummary(
        grade="F",
        grade_reason="Default credentials found.",
        score=85,
        target="192.168.1.0/24",
        device_count=2,
        open_ports=7,
        gateway_ip="192.168.1.1",
        devices_with_creds=1,
        findings=[
            Finding("CRITICAL", "Default credentials", "192.168.1.42", "admin / admin · ssh"),
            Finding("HIGH", "CVE-2023-1234", "192.168.1.42", "Known vulnerability"),
            Finding("LOW", "Missing security headers", "192.168.1.50", "Web service"),
        ],
        devices=[
            DeviceRow("192.168.1.42", "Hikvision", 5, "ssh", 85, "CRITICAL"),
            DeviceRow("192.168.1.50", "TP-Link", 2, "http", 30, "MEDIUM"),
        ],
    )


def test_grade_and_severity_style_maps():
    assert overview.grade_style("F") == "bold #DC0000" or "DC0000" in overview.grade_style("F")
    assert overview.severity_style("CRITICAL") == overview.severity_style("critical")
    # Unknown severity falls back without raising.
    assert overview.severity_style("BOGUS")


def test_build_overview_contains_key_data():
    text = _render(overview.build_overview(_summary()))
    assert "SECURITY GRADE" in text
    assert "F" in text
    assert "85 / 100" in text
    assert "NETWORK" in text
    assert "192.168.1.0/24" in text
    assert "TOP FINDINGS" in text
    assert "CRITICAL" in text
    assert "Default credentials" in text
    assert "DEVICES" in text
    assert "Hikvision" in text


def test_findings_panel_truncates_with_more_indicator():
    summary = _summary()
    summary.findings = [Finding("LOW", f"finding-{i}", "1.2.3.4", "") for i in range(10)]
    text = _render(overview.build_findings_panel(summary, limit=3))
    assert "and 7 more" in text


def test_findings_panel_empty_state():
    summary = _summary()
    summary.findings = []
    text = _render(overview.build_findings_panel(summary))
    assert "No findings" in text


def test_build_overview_empty_when_none():
    text = _render(overview.build_overview(None))
    assert "No assessment yet" in text
    assert "quick scan" in text


def test_build_overview_narrow_stacks_cards():
    summary = _summary()
    # Narrow still shows every card; render at a small width without error.
    console = Console(width=46, file=None, record=True)
    console.print(overview.build_overview(summary, narrow=True))
    text = console.export_text()
    assert "SECURITY GRADE" in text
    assert "NETWORK" in text
    assert "DEVICES" in text


def test_findings_view_lists_all_findings():
    summary = _summary()
    summary.findings = [Finding("LOW", f"finding-{i}", "1.2.3.4", "") for i in range(10)]
    text = _render(overview.build_findings_view(summary))
    # Unlike the overview panel, the dedicated view is not truncated.
    assert "finding-0" in text
    assert "finding-9" in text
    assert "more" not in text


def test_findings_view_none_and_empty_states():
    assert "No assessment yet" in _render(overview.build_findings_view(None))
    summary = _summary()
    summary.findings = []
    assert "No findings" in _render(overview.build_findings_view(summary))


def test_findings_view_filters_by_query():
    summary = _summary()
    # Query matches only the CVE finding's title.
    text = _render(overview.build_findings_view(summary, query="cve"))
    assert "CVE-2023-1234" in text
    assert "Default credentials" not in text
    # A non-matching query shows the empty-filter message.
    assert "No findings match" in _render(overview.build_findings_view(summary, query="zzz"))
    # Matching is case-insensitive and spans host/detail too.
    assert "Default credentials" in _render(
        overview.build_findings_view(summary, query="192.168.1.42")
    )
