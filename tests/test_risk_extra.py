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
    reports = [{"risk": {"score": 10, "factors": {"credentials": 0, "sql": 0, "web": 0}}}]
    grade, msg, color = RiskEngine.calculate_network_grade(reports)
    assert grade == "A"

    reports_vuln = [{"risk": {"score": 90, "factors": {"credentials": 10, "sql": 0, "web": 0}}}]
    grade, msg, color = RiskEngine.calculate_network_grade(reports_vuln)
    assert grade == "F"


def test_risk_engine_sql_web_init():
    port_data = {"hosts": [{"ip": "1.1.1.1", "tcp": []}]}
    cred_data = {"results": []}
    cve_data = {"results": []}
    sql_data = {"results": [{"ip": "1.1.1.1", "service": "mysql", "status": "successful"}]}
    web_data = {
        "results": [{"ip": "1.1.1.1", "protocol": "http", "port": 80, "sensitive_files": [".env"]}]
    }

    re = RiskEngine(port_data, cred_data, cve_data, sql_data=sql_data, web_data=web_data)
    assert "1.1.1.1" in re._sql_index
    assert "1.1.1.1" in re._web_index

    risk = re.calculate_device_risk("1.1.1.1")
    assert risk["score"] > 0
    assert len(risk["sql_findings"]) > 0
    assert len(risk["web_findings"]) > 0


def test_risk_engine_gateway_prioritization():
    port_data = {"hosts": [{"ip": "192.168.1.1", "tcp": [{"port": 80}]}]}
    cred_data = {"results": []}
    cve_data = {"results": []}

    # Without gateway IP
    re1 = RiskEngine(port_data, cred_data, cve_data)
    risk1 = re1.calculate_device_risk("192.168.1.1")

    # With gateway IP
    re2 = RiskEngine(port_data, cred_data, cve_data, gateway_ip="192.168.1.1")
    risk2 = re2.calculate_device_risk("192.168.1.1")

    assert risk2["score"] > risk1["score"]
    assert risk2["is_gateway"] is True


def test_calculate_network_grade_gateway_critical():
    reports = [
        {
            "risk": {
                "score": 90,
                "is_gateway": True,
                "factors": {"credentials": 10, "sql": 0, "web": 0},
            }
        }
    ]
    grade, msg, color = RiskEngine.calculate_network_grade(reports)
    assert grade == "F"
    assert "GATEWAY" in msg


def test_calculate_network_grade_various():
    # Grade D
    reports_d = [{"risk": {"score": 85, "factors": {"credentials": 0, "sql": 0, "web": 0}}}]
    grade, _, _ = RiskEngine.calculate_network_grade(reports_d)
    assert grade == "D"

    # Grade C
    reports_c = [{"risk": {"score": 55, "factors": {"credentials": 0, "sql": 0, "web": 0}}}]
    grade, _, _ = RiskEngine.calculate_network_grade(reports_c)
    assert grade == "C"

    # Grade B
    reports_b = [{"risk": {"score": 30, "factors": {"credentials": 0, "sql": 0, "web": 0}}}]
    grade, _, _ = RiskEngine.calculate_network_grade(reports_b)
    assert grade == "B"

    # Grade A+
    reports_ap = [{"risk": {"score": 0, "factors": {"credentials": 0, "sql": 0, "web": 0}}}]
    grade, _, _ = RiskEngine.calculate_network_grade(reports_ap)
    assert grade == "A+"
