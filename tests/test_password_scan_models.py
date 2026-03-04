# Third Party
import pytest
from pydantic import IPvAnyAddress

# First Party
from edgewalker.modules.password_scan.models import (
    CredentialsModel,
    PasswordScanModel,
    PasswordScanResultModel,
    ServiceEnum,
    StatusEnum,
)


def test_credentials_model():
    creds = CredentialsModel(user="admin", password="password123")
    assert creds["user"] == "admin"
    assert creds["password"] == "password123"
    assert creds.get("user") == "admin"
    assert creds.get("nonexistent", "default") == "default"


def test_password_scan_result_model():
    creds = CredentialsModel(user="admin", password="password123")
    result = PasswordScanResultModel(
        ip="192.168.1.1",
        port=22,
        service=ServiceEnum.ssh,
        login_attempt=StatusEnum.successful,
        credentials=creds,
    )

    # String access
    assert result["ip"] == IPvAnyAddress("192.168.1.1")
    assert result.get("port") == 22
    assert result.get("nonexistent", "default") == "default"

    # Integer access (backward compatibility)
    assert result[0] == "ssh"
    res_dict = result[1]
    assert res_dict["port"] == 22
    assert res_dict["status"] == "vulnerable"
    assert res_dict["credentials"] == [{"username": "admin", "password": "password123"}]

    # Failed attempt
    result_failed = PasswordScanResultModel(
        ip="192.168.1.1",
        port=22,
        service=ServiceEnum.ssh,
        login_attempt=StatusEnum.failed,
    )
    assert result_failed[1]["status"] == "secure"

    # Port closed
    result_closed = PasswordScanResultModel(
        ip="192.168.1.1",
        port=22,
        service=ServiceEnum.ssh,
        login_attempt=StatusEnum.failed,
        error="port_closed",
    )
    assert result_closed[1]["status"] == "port_closed"

    # Error cases
    with pytest.raises(IndexError):
        result[2]
    with pytest.raises(TypeError):
        result[None]
    with pytest.raises(KeyError):
        result["nonexistent"]


def test_password_scan_result_serialization():
    result = PasswordScanResultModel(
        ip="192.168.1.1",
        port=22,
        service=ServiceEnum.ssh,
        login_attempt=StatusEnum.successful,
    )

    # Default serialization
    data = result.model_dump(mode="json")
    assert data["ip"] == "192.168.1.1"

    # Public mode serialization
    data_public = result.model_dump(mode="json", context={"mode": "public"})
    assert data_public["ip"] == "0.0.1.1"

    # IPv6 Public mode serialization
    result_v6 = PasswordScanResultModel(
        ip="2001:db8::1",
        port=22,
        service=ServiceEnum.ssh,
        login_attempt=StatusEnum.successful,
    )
    data_v6_public = result_v6.model_dump(mode="json", context={"mode": "public"})
    assert data_v6_public["ip"] == "0000:0000:0000:0000:0000:0000:0000:0001"


def test_password_scan_model():
    model = PasswordScanModel(results=[])
    assert model.get("results") == []
    assert model["results"] == []

    with pytest.raises(TypeError):
        model[123]
    with pytest.raises(KeyError):
        model["nonexistent"]
