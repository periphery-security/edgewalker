# Standard Library
from unittest.mock import patch

# Third Party
import pytest
from rich.panel import Panel

# First Party
from edgewalker import display


@pytest.fixture
def sample_port_data():
    return {
        "target": "192.168.1.0/24",
        "scan_type": "quick",
        "timestamp": "2026-02-25T10:00:00",
        "duration_seconds": 30.5,
        "hosts_responded": 2,
        "hosts_with_ports": 1,
        "hosts": [
            {
                "ip": "192.168.1.10",
                "hostname": "test-device",
                "state": "up",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Test Vendor",
                "os": ["Linux 5.x"],
                "tcp": [
                    {
                        "port": 80,
                        "service": "http",
                        "name": "Apache",
                        "product": "Apache",
                        "version": "2.4.50",
                    }
                ],
            },
            {
                "ip": "192.168.1.1",
                "state": "down",
                "mac": "00:00:00:00:00:00",
                "tcp": [],
            },
        ],
    }


@pytest.fixture
def sample_cred_data():
    return {
        "results": [
            {
                "ip": "192.168.1.10",
                "port": 22,
                "service": "ssh",
                "login_attempt": "successful",
                "credentials": {"user": "admin", "password": "password"},
            }
        ],
        "summary": {
            "total_hosts": 1,
            "vulnerable_hosts": 1,
            "services_tested": 1,
            "credentials_found": 1,
        },
    }


@pytest.fixture
def sample_cve_data():
    return {
        "results": [
            {
                "ip": "192.168.1.10",
                "port": 80,
                "service": "http",
                "product": "Apache",
                "version": "2.4.50",
                "cves": [
                    {
                        "id": "CVE-2021-41773",
                        "description": "Path traversal and file disclosure",
                        "severity": "CRITICAL",
                        "score": 9.8,
                    }
                ],
            }
        ],
        "summary": {
            "total_services": 1,
            "services_with_cves": 1,
            "total_cves": 1,
            "critical_cves": 1,
            "high_cves": 0,
            "skipped_no_version": 0,
        },
    }


def test_build_telemetry_panel():
    panel = display.build_telemetry_panel()
    assert isinstance(panel, Panel)
    assert "HELP IMPROVE EDGEWALKER" in str(panel.title)


def test_build_mode_panel(tmp_path):
    # First Party
    from edgewalker.core.config import settings

    old_dir = settings.output_dir
    settings.output_dir = tmp_path
    try:
        panel = display.build_mode_panel()
        assert isinstance(panel, Panel)
        assert "SELECT MODE" in str(panel.title)

        # Test with report existing
        (tmp_path / "security_report.json").touch()
        panel = display.build_mode_panel()
        assert "View Last Report" in str(panel.renderable)
    finally:
        settings.output_dir = old_dir


def test_build_scan_type_panel():
    panel = display.build_scan_type_panel()
    assert isinstance(panel, Panel)
    assert "SELECT SCAN TYPE" in str(panel.title)


def test_build_status_panel():
    # Test initial state
    mock_status = {
        "port_scan": False,
        "port_scan_type": None,
        "password_scan": False,
        "cve_scan": False,
        "devices_found": 0,
        "vulnerable_devices": 0,
        "cves_found": 0,
    }
    with patch("edgewalker.utils.get_scan_status", return_value=mock_status):
        panel = display.build_status_panel()
        assert "NO PORT SCAN DATA" in str(panel.renderable)

    # Test port scan complete, others missing
    mock_status.update({"port_scan": True, "port_scan_type": "quick", "devices_found": 5})
    with patch("edgewalker.utils.get_scan_status", return_value=mock_status):
        panel = display.build_status_panel()
        assert "QUICK SCAN COMPLETE" in str(panel.renderable)

    # Test all complete
    mock_status.update({
        "password_scan": True,
        "cve_scan": True,
        "vulnerable_devices": 1,
        "cves_found": 1,
    })
    with patch("edgewalker.utils.get_scan_status", return_value=mock_status):
        panel = display.build_status_panel()
        assert "VULNERABILITIES FOUND" in str(panel.renderable)


def test_build_port_scan_display(sample_port_data):
    renderables = display.build_port_scan_display(sample_port_data)
    assert len(renderables) > 0
    # Use a more robust check for Rich objects
    # Third Party
    from rich.console import Console

    console = Console()
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "192.168.1.10" in output


def test_build_credential_display(sample_cred_data):
    # Vulnerable
    renderables = display.build_credential_display(sample_cred_data)
    assert len(renderables) > 0
    # Third Party
    from rich.console import Console

    console = Console()
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "DEFAULT CREDENTIALS FOUND" in output

    # Secure
    sample_cred_data["summary"]["vulnerable_hosts"] = 0
    sample_cred_data["results"] = []
    renderables = display.build_credential_display(sample_cred_data)
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "No default credentials found" in output


def test_build_cve_display(sample_cve_data):
    # Vulnerabilities found
    renderables = display.build_cve_display(sample_cve_data)
    assert len(renderables) > 0
    # Third Party
    from rich.console import Console

    console = Console()
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "VULNERABILITIES FOUND" in output

    # No vulnerabilities
    sample_cve_data["summary"]["total_cves"] = 0
    sample_cve_data["results"] = []
    renderables = display.build_cve_display(sample_cve_data)
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "No known CVEs found" in output


def test_build_risk_report(sample_port_data, sample_cred_data, sample_cve_data):
    # Full report
    renderables, report_data = display.build_risk_report(
        sample_port_data, sample_cred_data, sample_cve_data
    )
    assert len(renderables) > 0
    assert report_data["network_grade"] in ["A+", "A", "B", "C", "D", "F"]
    assert report_data["summary"]["total_devices"] == 1

    # Verify new tables are present
    # Third Party
    from rich.console import Console

    console = Console()
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "VULNERABLE CREDENTIALS" in output
    assert "KNOWN VULNERABILITIES (CVEs)" in output
    assert "admin:password" in output
    assert "CVE-2021-41773" in output

    # Test empty devices
    sample_port_data["hosts"] = []
    renderables, report_data = display.build_risk_report(
        sample_port_data, sample_cred_data, sample_cve_data
    )
    # Third Party
    from rich.console import Console

    console = Console()
    with console.capture() as capture:
        for r in renderables:
            console.print(r)
    output = capture.get()
    assert "No devices found" in output

    # Test clean devices
    sample_port_data["hosts"] = [
        {"ip": "1.1.1.1", "state": "up", "mac": "00:00:00:00:00:00", "tcp": []}
    ]
    sample_cred_data["results"] = []
    sample_cve_data["results"] = []
    renderables, report_data = display.build_risk_report(
        sample_port_data, sample_cred_data, sample_cve_data
    )
    assert report_data["network_grade"] == "A+"
