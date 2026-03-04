# Standard Library

# Third Party
from rich.panel import Panel

# First Party
from edgewalker import display


def test_build_port_scan_display():
    results = {
        "hosts": [
            {
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "vendor": "Local",
                "tcp": [{"port": 80, "name": "http"}],
            }
        ]
    }
    renderables = display.build_port_scan_display(results)
    assert len(renderables) == 1
    assert isinstance(renderables[0], Panel)


def test_build_credential_display():
    results = {
        "results": [
            {
                "ip": "127.0.0.1",
                "port": 22,
                "service": "ssh",
                "login_attempt": "successful",
                "credentials": {"user": "admin", "password": "password"},
            }
        ]
    }
    renderables = display.build_credential_display(results)
    assert len(renderables) == 1
    assert "DEFAULT CREDENTIALS FOUND" in str(renderables[0].title)


def test_build_cve_display():
    results = {
        "results": [
            {
                "ip": "127.0.0.1",
                "port": 80,
                "service": "http",
                "product": "test",
                "version": "1.0",
                "cves": [{"id": "CVE-1", "description": "test", "severity": "HIGH", "score": 7.5}],
            }
        ]
    }
    renderables = display.build_cve_display(results)
    assert len(renderables) == 1
    assert "VULNERABILITIES FOUND" in str(renderables[0].title)


def test_build_risk_report():
    port_data = {
        "hosts": [
            {
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "state": "up",
                "vendor": "Local",
                "tcp": [{"port": 80, "name": "http"}],
            }
        ]
    }
    cred_data = {"results": []}
    cve_data = {"results": []}

    renderables, report_data = display.build_risk_report(port_data, cred_data, cve_data)
    assert len(renderables) > 0
    assert report_data["network_grade"] is not None


def test_build_panels():
    assert isinstance(display.build_mode_panel(), Panel)
    assert isinstance(display.build_status_panel(), Panel)
    assert isinstance(display.build_telemetry_panel(), Panel)
    assert isinstance(display.build_scan_type_panel(), Panel)
