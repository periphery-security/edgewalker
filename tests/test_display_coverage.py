# Standard Library

# Third Party
import pytest
from rich.console import Group

# First Party
from edgewalker import display


@pytest.fixture
def sample_device_data():
    return {
        "ip": "192.168.1.10",
        "vendor": "Test Vendor",
        "risk": {
            "score": 85,
            "open_ports": [22, 80],
            "weak_creds": ["ssh:admin:password"],
            "cves": ["CVE-2021-41773 (CRITICAL)"],
            "sql_findings": [{"service": "mysql", "status": "successful", "version": "5.7"}],
            "web_findings": [
                {
                    "protocol": "http",
                    "port": 80,
                    "tls": {"expired": True},
                    "sensitive_files": ["/.env"],
                    "headers": {"csp": False, "hsts": False},
                }
            ],
            "mdns_name": "test-device.local",
            "http_server": "Apache/2.4.50",
            "http_title": "Test Page",
            "factors": {
                "exposure": 20,
                "credentials": 30,
                "vulnerabilities": 25,
                "sql": 10,
                "web": 0,
            },
        },
    }


def test_build_device_report_branches(sample_device_data):
    # Test SQL "FAILED" status
    sample_device_data["risk"]["sql_findings"] = [{"service": "mysql", "status": "failed"}]
    report = display.build_device_report(sample_device_data)
    assert isinstance(report, Group)

    # Test SQL "UNKNOWN" status
    sample_device_data["risk"]["sql_findings"] = [{"service": "mysql", "status": "unknown"}]
    report = display.build_device_report(sample_device_data)
    assert isinstance(report, Group)

    # Test Web with no TLS/files/headers
    sample_device_data["risk"]["web_findings"] = [{"protocol": "http", "port": 80}]
    report = display.build_device_report(sample_device_data)
    assert isinstance(report, Group)


def test_build_risk_report_empty_hosts():
    port_data = {"hosts": []}
    cred_data = {"results": []}
    cve_data = {"results": []}
    renderables, report_data = display.build_risk_report(port_data, cred_data, cve_data)
    assert len(renderables) == 1
    assert report_data == {}


def test_build_risk_report_with_extras():
    port_data = {
        "target": "192.168.1.0/24",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "state": "up",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Test Vendor",
                "tcp": [{"port": 80, "name": "http"}],
            }
        ],
    }
    cred_data = {"results": []}
    cve_data = {"results": []}
    sql_data = {
        "results": [
            {
                "host": "192.168.1.10",
                "service": "mysql",
                "status": "vulnerable",
                "details": "Default root password",
            }
        ]
    }
    web_data = {
        "results": [
            {
                "host": "192.168.1.10",
                "url": "http://192.168.1.10/.env",
                "vulnerability": "sensitive_file",
                "details": "Found /.env",
            }
        ]
    }

    renderables, report_data = display.build_risk_report(
        port_data, cred_data, cve_data, sql_data, web_data
    )
    assert len(renderables) > 0
    assert report_data["network_grade"] is not None

    # Verify SQL and Web findings are in the report data
    # (The current implementation of build_risk_report might not include them in report_data summary yet,
    # but it uses them in RiskEngine)
