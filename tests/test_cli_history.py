# Third Party
from rich.console import Group
from typer.testing import CliRunner

# First Party
from edgewalker.cli.cli import app
from edgewalker.tui.widgets.overview import (
    build_comparison_view,
    build_history_view,
    build_report_list_view,
    history_sparkline,
)


def test_sparkline_empty():
    assert history_sparkline([]) == ""


def test_sparkline_maps_range_to_blocks():
    spark = history_sparkline([0, 50, 100])
    assert spark[0] == "▁" and spark[-1] == "█"
    assert len(spark) == 3


def _render(group: Group) -> str:
    # Render the Group to plain text for assertions.
    # Third Party
    from rich.console import Console

    console = Console(width=120, record=True)
    console.print(group)
    return console.export_text()


def test_build_history_view_empty_shows_message():
    out = build_history_view([], [])
    assert isinstance(out, Group)
    assert "No history yet" in _render(out)


def test_build_history_view_renders_trend_and_table():
    events = [
        {
            "created_at": "2026-06-15T12:00:00+00:00",
            "event_type": "port_opened",
            "severity": "HIGH",
            "detail": {"port": 23},
            "stable_key": "mac:00:11:22:33:44:55",
            "label": None,
        }
    ]
    trend = [{"at": "t1", "score": 90, "grade": "A"}, {"at": "t2", "score": 50, "grade": "D"}]
    text = _render(build_history_view(events, trend))
    assert "Score trend" in text
    assert "port_opened" in text
    assert "Recent changes" in text


def test_build_history_view_renders_web_and_sql_events():
    events = [
        {
            "created_at": "2026-06-15T12:00:00+00:00",
            "event_type": "web_issue_appeared",
            "severity": "CRITICAL",
            "detail": {"issue": "sensitive_file"},
            "stable_key": "mac:00:11:22:33:44:55",
            "label": None,
        },
        {
            "created_at": "2026-06-15T12:00:00+00:00",
            "event_type": "sql_vuln_appeared",
            "severity": "CRITICAL",
            "detail": {"service": "mysql"},
            "stable_key": "mac:00:11:22:33:44:55",
            "label": None,
        },
    ]
    text = _render(build_history_view(events, []))
    assert "web_issue_appeared" in text
    assert "sensitive file" in text  # underscores humanised
    assert "sql_vuln_appeared" in text
    assert "mysql" in text


def test_build_report_list_view_empty():
    assert "No reports yet" in _render(build_report_list_view([]))


def test_build_report_list_view_lists_reports():
    reports = [
        {"ordinal": 2, "at": "2026-06-15T14:10:00+00:00", "score": 58, "grade": "D", "target": "n"},
        {"ordinal": 1, "at": "2026-06-10T18:30:00+00:00", "score": 80, "grade": "B", "target": "n"},
    ]
    text = _render(build_report_list_view(reports))
    assert "Reports" in text
    assert "2026-06-15 14:10:00" in text
    assert "D" in text and "B" in text


def test_build_comparison_view_renders_changes_and_grade_move():
    comparison = {
        "from": {"ordinal": 1, "at": "2026-06-10T18:30:00+00:00", "score": 80, "grade": "B"},
        "to": {"ordinal": 2, "at": "2026-06-15T14:10:00+00:00", "score": 58, "grade": "D"},
        "changes": [
            {
                "created_at": "2026-06-12T09:00:00+00:00",
                "event_type": "port_opened",
                "severity": "HIGH",
                "detail": {"port": 23},
                "stable_key": "mac:aa",
                "label": None,
            }
        ],
    }
    text = _render(build_comparison_view(comparison))
    assert "Comparing" in text
    assert "#1" in text and "#2" in text
    assert "grade" in text and "B" in text and "D" in text
    assert "port_opened" in text


def test_build_comparison_view_no_changes():
    comparison = {
        "from": {"ordinal": 1, "at": "t1", "score": 80, "grade": "B"},
        "to": {"ordinal": 2, "at": "t2", "score": 80, "grade": "B"},
        "changes": [],
    }
    assert "No material changes" in _render(build_comparison_view(comparison))


def test_history_command_runs_with_empty_db(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.db_path = tmp_path / "edgewalker.db"
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No history yet" in result.stdout


def _seed_assessments(tmp_path):
    # First Party
    from edgewalker.core.config import settings
    from edgewalker.core.sqlite_store import SqliteResultStore

    settings.db_path = tmp_path / "edgewalker.db"
    store = SqliteResultStore(settings.db_path)
    store.record_assessment("net", 80, "B")
    store.record_assessment("net", 58, "D")
    return store


def test_history_list_flag_shows_reports(tmp_path):
    _seed_assessments(tmp_path)
    result = CliRunner().invoke(app, ["history", "--list"])
    assert result.exit_code == 0
    assert "Reports" in result.stdout


def test_compare_command_renders_comparison(tmp_path):
    _seed_assessments(tmp_path)
    result = CliRunner().invoke(app, ["compare", "1", "2"])
    assert result.exit_code == 0
    assert "Comparing" in result.stdout


def test_compare_command_invalid_reports_exits_nonzero(tmp_path):
    _seed_assessments(tmp_path)
    result = CliRunner().invoke(app, ["compare", "1", "9"])
    assert result.exit_code == 1
