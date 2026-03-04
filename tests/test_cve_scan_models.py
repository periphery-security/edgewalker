# Third Party
import pytest
from pydantic import IPvAnyAddress

# First Party
from edgewalker.modules.cve_scan.models import CveModel, CveScanModel, CveScanResultModel


def test_cve_model():
    cve = CveModel(id="CVE-2021-1234", description="Test CVE", severity="High", score=8.5)
    assert cve["id"] == "CVE-2021-1234"
    assert cve.get("severity") == "High"
    assert cve.get("nonexistent", "default") == "default"


def test_cve_scan_result_model():
    cve = CveModel(id="CVE-2021-1234", description="Test CVE", severity="High", score=8.5)
    result = CveScanResultModel(
        ip="192.168.1.1",
        port=80,
        service="http",
        product="nginx",
        version="1.18",
        cves=[cve],
    )

    assert result["ip"] == IPvAnyAddress("192.168.1.1")
    assert result.get("product") == "nginx"
    assert result.get("nonexistent", "default") == "default"


def test_cve_scan_result_serialization():
    result = CveScanResultModel(
        ip="192.168.1.1",
        port=80,
        service="http",
        product="nginx",
        version="1.18",
    )

    # Default serialization
    data = result.model_dump(mode="json")
    assert data["ip"] == "192.168.1.1"

    # Public mode serialization
    data_public = result.model_dump(mode="json", context={"mode": "public"})
    assert data_public["ip"] == "0.0.1.1"

    # IPv6 Public mode serialization
    result_v6 = CveScanResultModel(
        ip="2001:db8::1",
        port=80,
        service="http",
        product="nginx",
        version="1.18",
    )
    data_v6_public = result_v6.model_dump(mode="json", context={"mode": "public"})
    assert data_v6_public["ip"] == "0000:0000:0000:0000:0000:0000:0000:0001"


def test_cve_scan_model():
    model = CveScanModel(results=[])
    assert model.get("results") == []
    assert model["results"] == []

    with pytest.raises(TypeError):
        model[123]
    with pytest.raises(KeyError):
        model["nonexistent"]
