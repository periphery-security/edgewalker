# Standard Library
import json
from unittest.mock import MagicMock

# Third Party
import pytest

# First Party
from edgewalker.core.result_store import CompositeStore, JsonResultStore, ResultStore
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.port_scan.models import Host, PortScanModel


@pytest.fixture
def store(tmp_path):
    """A JsonResultStore writing into a temp output dir."""
    # First Party
    from edgewalker.core.config import settings

    settings.output_dir = tmp_path
    return JsonResultStore(), tmp_path


def test_json_store_satisfies_protocol():
    assert isinstance(JsonResultStore(), ResultStore)


def test_save_scan_writes_latest_and_snapshot(store):
    s, out = store
    model = PortScanModel(target="10.0.0.0/24", device_id="dev123")
    path = s.save_scan("port_scan", model)

    # Canonical "latest" file is returned and written.
    assert path == out / "port_scan.json"
    assert (out / "port_scan.json").exists()
    # Per-device snapshot is kept by default.
    assert (out / "port_scan_dev123.json").exists()

    data = json.loads((out / "port_scan.json").read_text())
    assert data["target"] == "10.0.0.0/24"


def test_save_scan_without_snapshot_writes_only_latest(store):
    s, out = store
    model = CveScanModel(results=[], device_id="dev123")
    s.save_scan("cve_scan", model, keep_snapshot=False)

    assert (out / "cve_scan.json").exists()
    assert not (out / "cve_scan_dev123.json").exists()


def test_get_latest_port_scan_roundtrip(store):
    s, _ = store
    model = PortScanModel(
        target="10.0.0.0/24",
        hosts=[Host(ip="10.0.0.5", mac="00:11:22:33:44:55", state="up")],
    )
    s.save_scan("port_scan", model)

    loaded = s.get_latest_port_scan()
    assert loaded is not None
    assert loaded.target == "10.0.0.0/24"
    assert len(loaded.hosts) == 1
    assert str(loaded.hosts[0].ip) == "10.0.0.5"


def test_get_latest_port_scan_returns_none_when_absent(store):
    s, _ = store
    assert s.get_latest_port_scan() is None


# --- record_assessment + CompositeStore ------------------------------------


def test_json_store_record_assessment_is_noop(store):
    s, _ = store
    # Must not raise and must not create any file.
    assert s.record_assessment("10.0.0.0/24", 80.0, "B") is None


def test_composite_satisfies_protocol():
    assert isinstance(CompositeStore(JsonResultStore()), ResultStore)


def test_composite_writes_to_all_stores_and_returns_primary_path():
    primary, secondary = MagicMock(), MagicMock()
    primary.save_scan.return_value = "/tmp/port_scan.json"
    composite = CompositeStore(primary, secondary)

    model = PortScanModel(target="t")
    path = composite.save_scan("port_scan", model)

    assert path == "/tmp/port_scan.json"  # primary's path is returned
    primary.save_scan.assert_called_once()
    secondary.save_scan.assert_called_once()  # secondary got the write too


def test_composite_reads_from_primary_only():
    primary, secondary = MagicMock(), MagicMock()
    primary.get_latest_port_scan.return_value = "sentinel"
    composite = CompositeStore(primary, secondary)

    assert composite.get_latest_port_scan() == "sentinel"
    secondary.get_latest_port_scan.assert_not_called()


def test_composite_record_assessment_fans_out():
    primary, secondary = MagicMock(), MagicMock()
    CompositeStore(primary, secondary).record_assessment("t", 50.0, "C")
    primary.record_assessment.assert_called_once_with("t", 50.0, "C")
    secondary.record_assessment.assert_called_once_with("t", 50.0, "C")
