# Standard Library

# Third Party

# First Party
from edgewalker.core.risk import RiskEngine


def test_risk_engine_init_model():
    port_data = {
        "hosts": [
            {"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 80, "name": "http"}]}
        ]
    }
    cred_data = {
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
    cve_data = {
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

    re = RiskEngine(port_data, cred_data, cve_data)
    assert "127.0.0.1" in re._port_index
    assert "127.0.0.1" in re._cred_index
    assert "127.0.0.1" in re._cve_index


def test_risk_engine_init_legacy():
    port_data = {
        "hosts": [
            {"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 80, "name": "http"}]}
        ]
    }
    cred_data = {"hosts": [{"host": "127.0.0.1", "services": {"ssh": {"status": "vulnerable"}}}]}
    cve_data = {
        "hosts": [
            {"ip": "127.0.0.1", "services": [{"cves": [{"id": "CVE-1", "severity": "HIGH"}]}]}
        ]
    }

    re = RiskEngine(port_data, cred_data, cve_data)
    assert "127.0.0.1" in re._port_index
    assert "127.0.0.1" in re._cred_index
    assert "127.0.0.1" in re._cve_index


def test_calculate_device_risk():
    port_data = {
        "hosts": [
            {"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 80, "name": "http"}]}
        ]
    }
    cred_data = {"results": []}
    cve_data = {"results": []}

    re = RiskEngine(port_data, cred_data, cve_data)
    risk = re.calculate_device_risk("127.0.0.1")
    assert risk["score"] > 0
    assert "80/http" in risk["open_ports"]


def test_calculate_network_grade():
    reports = [{"risk": {"score": 10, "factors": {"credentials": 0}}}]
    grade, msg, color = RiskEngine.calculate_network_grade(reports)
    assert grade == "A"

    reports_vuln = [{"risk": {"score": 90, "factors": {"credentials": 10}}}]
    grade, msg, color = RiskEngine.calculate_network_grade(reports_vuln)
    assert grade == "F"
