# First Party
from edgewalker.core.risk import RiskEngine


def test_calculate_device_risk_clean():
    """Test risk calculation for a clean device."""
    ip = "192.168.1.1"
    port_data = {"hosts": [{"ip": ip, "mac": "00:00:00:00:00:00", "tcp": []}]}
    cred_data = {"results": []}
    cve_data = {"results": []}

    engine = RiskEngine(port_data, cred_data, cve_data)
    res = engine.calculate_device_risk(ip)
    assert res["score"] == 0
    assert not res["open_ports"]


def test_calculate_device_risk_vulnerable():
    """Test risk calculation for a vulnerable device."""
    ip = "192.168.1.10"
    port_data = {
        "hosts": [
            {
                "ip": ip,
                "mac": "00:00:00:00:00:00",
                "tcp": [{"port": 23, "name": "telnet"}, {"port": 80, "name": "http"}],
            }
        ]
    }
    cred_data = {
        "results": [
            {
                "ip": ip,
                "port": 23,
                "service": "telnet",
                "login_attempt": "successful",
                "credentials": {"user": "admin", "password": "admin"},
            }
        ]
    }
    cve_data = {
        "results": [
            {
                "ip": ip,
                "port": 80,
                "service": "http",
                "product": "test",
                "version": "1.0",
                "cves": [
                    {
                        "id": "CVE-2023-1234",
                        "description": "test",
                        "severity": "CRITICAL",
                        "score": 10.0,
                    }
                ],
            }
        ]
    }

    engine = RiskEngine(port_data, cred_data, cve_data)
    res = engine.calculate_device_risk(ip)
    assert res["score"] > 20
    assert "23/telnet" in res["open_ports"]
    assert "telnet" in res["weak_creds"]
    assert "CVE-2023-1234 (CRITICAL)" in res["cves"]


def test_calculate_network_grade():
    """Test network grading logic."""
    devices = [
        {"risk": {"score": 10, "factors": {"credentials": 0}, "weak_creds": [], "cves": []}},
        {"risk": {"score": 30, "factors": {"credentials": 0}, "weak_creds": [], "cves": []}},
    ]
    grade, reason, _ = RiskEngine.calculate_network_grade(devices)
    assert grade == "B"

    devices.append({
        "risk": {
            "score": 90,
            "factors": {"credentials": 100},
            "weak_creds": ["SSH: root"],
            "cves": [],
        }
    })
    grade, reason, _ = RiskEngine.calculate_network_grade(devices)
    assert grade == "F"
    assert "credentials" in reason
