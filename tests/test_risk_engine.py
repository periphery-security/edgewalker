# First Party
from edgewalker.core.risk import RiskEngine


def test_risk_engine_legacy_formats():
    # Legacy credential format
    port_data = {
        "hosts": [
            {"ip": "1.1.1.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 80, "name": "http"}]}
        ]
    }
    cred_data = {"hosts": [{"host": "1.1.1.1", "services": {"ssh": {"status": "vulnerable"}}}]}
    cve_data = {
        "hosts": [{"ip": "1.1.1.1", "services": [{"cves": [{"id": "CVE-1", "severity": "HIGH"}]}]}]
    }

    engine = RiskEngine(port_data, cred_data, cve_data)
    assert "1.1.1.1" in engine._cred_index
    assert engine._cred_index["1.1.1.1"] == ["ssh"]
    assert "1.1.1.1" in engine._cve_index
    assert len(engine._cve_index["1.1.1.1"]) == 1


def test_calculate_device_risk_full():
    port_data = {
        "hosts": [
            {"ip": "1.1.1.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 22, "name": "ssh"}]}
        ]
    }
    cred_data = {"results": [{"ip": "1.1.1.1", "service": "ssh", "login_attempt": "successful"}]}
    cve_data = {"results": [{"ip": "1.1.1.1", "cves": [{"id": "CVE-1", "severity": "CRITICAL"}]}]}

    engine = RiskEngine(port_data, cred_data, cve_data)
    risk = engine.calculate_device_risk("1.1.1.1")

    assert risk["score"] > 0
    assert "22/ssh" in risk["open_ports"]
    assert "ssh" in risk["weak_creds"]
    assert "CVE-1 (CRITICAL)" in risk["cves"]


def test_get_risk_level():
    assert RiskEngine.get_risk_level(90)[0] == "CRITICAL"
    assert RiskEngine.get_risk_level(60)[0] == "HIGH"
    assert RiskEngine.get_risk_level(30)[0] == "MEDIUM"
    assert RiskEngine.get_risk_level(10)[0] == "LOW"
    assert RiskEngine.get_risk_level(0)[0] == "NONE"


def test_calculate_device_risk_none():
    port_data = {"hosts": [{"ip": "1.1.1.1", "mac": "00:00:00:00:00:00", "tcp": []}]}
    cred_data = {"results": []}
    cve_data = {"results": []}

    engine = RiskEngine(port_data, cred_data, cve_data)
    risk = engine.calculate_device_risk("1.1.1.1")
    assert risk["score"] == 0
    assert risk["risk_level"] == "NONE"


def test_calculate_device_risk_unknowns():
    # Port not in settings.port_severity
    port_data = {
        "hosts": [
            {
                "ip": "1.1.1.1",
                "mac": "00:00:00:00:00:00",
                "tcp": [{"port": 9999, "name": "unknown"}],
            }
        ]
    }
    # Service not in settings.cred_severity
    cred_data = {
        "results": [{"ip": "1.1.1.1", "service": "unknown_svc", "login_attempt": "successful"}]
    }
    # Severity not in settings.cve_severity
    cve_data = {
        "results": [{"ip": "1.1.1.1", "cves": [{"id": "CVE-1", "severity": "UNKNOWN_LABEL"}]}]
    }

    engine = RiskEngine(port_data, cred_data, cve_data)
    risk = engine.calculate_device_risk("1.1.1.1")
    assert risk["score"] > 0


def test_calculate_network_grade():
    # No reports
    assert RiskEngine.calculate_network_grade([])[0] == "A"

    # Default credentials (F)
    reports = [{"risk": {"score": 10, "factors": {"credentials": 50}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "F"

    # High score (D)
    reports = [{"risk": {"score": 85, "factors": {"credentials": 0}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "D"

    # Mid score (C)
    reports = [{"risk": {"score": 55, "factors": {"credentials": 0}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "C"

    # Low score (B)
    reports = [{"risk": {"score": 30, "factors": {"credentials": 0}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "B"

    # Very low score (A)
    reports = [{"risk": {"score": 5, "factors": {"credentials": 0}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "A"

    # Zero score (A+)
    reports = [{"risk": {"score": 0, "factors": {"credentials": 0}}}]
    assert RiskEngine.calculate_network_grade(reports)[0] == "A+"
