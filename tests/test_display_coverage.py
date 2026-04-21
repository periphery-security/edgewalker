# Standard Library
import io
from unittest.mock import patch

# Third Party
import pytest
from rich.console import Console, Group

# First Party
from edgewalker import display


def render_to_string(renderable):
    """Helper to render a Rich object to a string for assertions."""
    console = Console(file=io.StringIO(), force_terminal=False, width=200)
    console.print(renderable)
    return console.file.getvalue()


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
                "tcp": [{"port": 80, "name": "http", "service": "http", "state": "open"}],
            }
        ],
        "summary": {"total_hosts": 1, "up_hosts": 1},
    }
    cred_data = {"results": []}
    cve_data = {"results": []}
    sql_data = {
        "results": [
            {
                "ip": "192.168.1.10",
                "service": "mysql",
                "status": "successful",
                "version": "5.7",
                "databases": ["test"],
            }
        ]
    }
    web_data = {
        "results": [
            {
                "ip": "192.168.1.10",
                "protocol": "http",
                "port": 80,
                "tls": {"expired": True},
                "sensitive_files": [".env"],
                "headers": {"csp": False, "hsts": False},
            }
        ]
    }

    renderables, report_data = display.build_risk_report(
        port_data, cred_data, cve_data, sql_data, web_data
    )
    assert len(renderables) > 0
    assert report_data["network_grade"] is not None


def test_build_credential_display_legacy():
    """Test build_credential_display with legacy data format."""
    legacy_data = {
        "hosts": [
            {
                "host": "1.1.1.1",
                "services": {
                    "ssh": {
                        "status": "vulnerable",
                        "credentials": [{"user": "root", "password": "root"}],
                    }
                },
            }
        ]
    }
    renderables = display.build_credential_display(legacy_data)
    assert len(renderables) > 0


def test_build_credential_display_empty():
    """Test build_credential_display with no results."""
    renderables = display.build_credential_display({"results": []})
    assert "No default credentials found" in render_to_string(renderables[0])


def test_build_cve_display_empty():
    """Test build_cve_display with no results."""
    renderables = display.build_cve_display({"results": []})
    assert "No known CVEs found" in render_to_string(renderables[0])


def test_build_device_report_empty_ports():
    """Test build_device_report with no open ports."""
    risk_data = {
        "score": 0,
        "level": "Low",
        "factors": {"credentials": 0, "vulnerabilities": 0, "exposure": 0, "sql": 0, "web": 0},
        "open_ports": [],
        "weak_creds": [],
        "vulnerabilities": [],
        "sql_findings": [],
        "web_findings": [],
        "remediations": [],
    }
    renderable = display.build_device_report({"ip": "1.1.1.1", "risk": risk_data})
    assert "No open ports discovered" in render_to_string(renderable)


def test_build_device_report_with_sql_failed():
    """Test build_device_report with failed SQL status."""
    risk_data = {
        "score": 0,
        "level": "Low",
        "factors": {"credentials": 0, "vulnerabilities": 0, "exposure": 0, "sql": 0, "web": 0},
        "open_ports": [],
        "weak_creds": [],
        "vulnerabilities": [],
        "sql_findings": [{"status": "failed", "service": "mysql"}],
        "web_findings": [],
        "remediations": [],
    }
    renderable = display.build_device_report({"ip": "1.1.1.1", "risk": risk_data})
    report_str = render_to_string(renderable).upper()
    assert "SECURE" in report_str or "FAILED" in report_str


def test_build_device_report_with_sql_other():
    """Test build_device_report with other SQL status."""
    risk_data = {
        "score": 0,
        "level": "Low",
        "factors": {"credentials": 0, "vulnerabilities": 0, "exposure": 0, "sql": 0, "web": 0},
        "open_ports": [],
        "weak_creds": [],
        "vulnerabilities": [],
        "sql_findings": [{"status": "error", "service": "mysql"}],
        "web_findings": [],
        "remediations": [],
    }
    renderable = display.build_device_report({"ip": "1.1.1.1", "risk": risk_data})
    assert "ERROR" in render_to_string(renderable).upper()


def test_build_device_report_with_remediations():
    """Test build_device_report with remediations."""
    risk_data = {
        "score": 50,
        "level": "Medium",
        "factors": {"credentials": 0, "vulnerabilities": 0, "exposure": 0, "sql": 0, "web": 0},
        "open_ports": [],
        "weak_creds": [],
        "vulnerabilities": [],
        "sql_findings": [],
        "web_findings": [],
        "remediations": [{"title": "Fix it", "remediation": "Step 1\nStep 2"}],
    }
    renderable = display.build_device_report({"ip": "1.1.1.1", "risk": risk_data})
    assert "REMEDIATIONS" in render_to_string(renderable).upper()
    assert "Step 1" in render_to_string(renderable)


def test_build_risk_report_with_discovery_names():
    """Test build_risk_report with mDNS and UPnP names."""
    port_data = {
        "hosts": [
            {
                "ip": "1.1.1.1",
                "mac": "00:11:22:33:44:55",
                "state": "up",
                "vendor": "Vendor",
                "tcp": [{"port": 80, "state": "open", "service": "http", "name": "http"}],
            }
        ],
        "summary": {"total_hosts": 1, "up_hosts": 1},
    }
    # Mock RiskEngine to return names
    with (
        patch("edgewalker.display.RiskEngine") as mock_engine_cls,
        patch(
            "edgewalker.display.RiskEngine.calculate_network_grade",
            return_value=("A", "Good", "green"),
        ),
        patch("edgewalker.display.RiskEngine.get_risk_level", return_value=("CRITICAL", "red")),
    ):
        mock_engine = mock_engine_cls.return_value
        mock_engine.calculate_device_risk.return_value = {
            "score": 80,
            "factors": {"credentials": 1, "vulnerabilities": 1, "exposure": 60, "sql": 0, "web": 0},
            "mdns_name": "MyDevice",
            "upnp_info": {"modelName": "ModelX"},
            "sql_findings": [],
            "web_findings": [],
            "cves": [],
            "open_ports": [],
            "raw_weak_creds": ["ssh"],  # Test non-dict cred
        }
        renderables, report_data = display.build_risk_report(port_data, {}, {})

        # Check individual panels
        found_device = False
        found_exposure = False
        for i, r in enumerate(renderables):
            r_str = render_to_string(r)
            print(f"Panel {i}: {r_str}")
            if "MyDevice" in r_str:
                found_device = True
            if "High" in r_str and "Exposure" in r_str:
                found_exposure = True

        assert found_device
        assert found_exposure
