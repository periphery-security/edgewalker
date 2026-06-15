# Standard Library
import json

# Third Party
import pytest

# First Party
from edgewalker.core.result_store import JsonResultStore, ResultStore
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
