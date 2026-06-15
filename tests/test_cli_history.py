# Third Party
from rich.table import Table
from rich.text import Text
from typer.testing import CliRunner

# First Party
from edgewalker.cli.cli import app
from edgewalker.cli.history import build_history_view, sparkline


def test_sparkline_empty():
    assert sparkline([]) == ""


def test_sparkline_maps_range_to_blocks():
    spark = sparkline([0, 50, 100])
    assert spark[0] == "▁" and spark[-1] == "█"
    assert len(spark) == 3


def test_build_history_view_empty_shows_message():
    out = build_history_view([], [])
    assert len(out) == 1
    assert isinstance(out[0], Text)
    assert "No history yet" in out[0].plain


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
    out = build_history_view(events, trend)
    # A trend Text line and a change-events Table.
    assert any(isinstance(r, Text) for r in out)
    assert any(isinstance(r, Table) for r in out)


def test_history_command_runs_with_empty_db(tmp_path, monkeypatch):
    # Point the DB at an isolated path (autouse isolate_db already does, but be explicit).
    # First Party
    from edgewalker.core.config import settings

    settings.db_path = tmp_path / "edgewalker.db"
    result = CliRunner().invoke(app, ["history"])
    assert result.exit_code == 0
    assert "No history yet" in result.stdout
