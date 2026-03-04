# Standard Library
from datetime import datetime, timezone

# Third Party
import pytest
import semver

# First Party
from edgewalker.core.models import Base, MacSearchResult, valid_version, validate_mac


def test_validate_mac():
    assert validate_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert validate_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert validate_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert validate_mac("001122334455") == "00:11:22:33:44:55"
    assert validate_mac("") == ""

    with pytest.raises(ValueError):
        validate_mac("invalid")
    with pytest.raises(ValueError):
        validate_mac("00:11:22:33:44:5G")


def test_valid_version():
    v = valid_version("1.2.3")
    assert isinstance(v, semver.VersionInfo)
    assert str(v) == "1.2.3"

    v2 = valid_version(v)
    assert v2 is v

    v3 = valid_version("1.2")
    assert str(v3) == "1.2.0"


def test_base_model():
    now = datetime.now(timezone.utc)
    base = Base(
        id="test-id",
        device_id="test-device",
        version="1.0.0",
        module="unspecified",
        module_version="0.1.0",
        timestamp=now,
    )

    assert base["id"] == "test-id"
    assert base.get("module") == "unspecified"
    assert base.get("nonexistent", "default") == "default"
    assert base.get(123, "default") == "default"

    with pytest.raises(TypeError):
        base[123]
    with pytest.raises(KeyError):
        base["nonexistent"]

    # Equality with dict
    dump = base.model_dump(mode="json")
    assert base == dump
    assert not (base == {"wrong": "dict"})
    assert not (base == "not-a-dict")


def test_base_serialization():
    base = Base(version="1.2.3", module_version="4.5.6")
    data = base.model_dump(mode="json")
    assert data["version"] == "1.2.3"
    assert data["module_version"] == "4.5.6"


def test_mac_search_result():
    res = MacSearchResult(
        mac_address="00:11:22:33:44:55",
        normalized_mac="001122334455",
        found=True,
        organization="Test Org",
    )
    assert res.mac_address == "00:11:22:33:44:55"
    assert res.found is True
    assert res.organization == "Test Org"
