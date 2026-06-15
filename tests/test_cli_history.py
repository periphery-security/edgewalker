# Third Party
from rich.console import Group
from typer.testing import CliRunner

# First Party
from edgewalker.cli.cli import app
from edgewalker.tui.widgets.overview import build_history_view, history_sparkline


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


def test_history_command_runs_with_empty_db(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    settings.db_path = tmp_path / "edgewalker.db"
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No history yet" in result.stdout
