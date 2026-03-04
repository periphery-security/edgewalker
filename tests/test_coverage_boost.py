# Standard Library
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker import utils
from edgewalker.core.risk import RiskEngine
from edgewalker.core.telemetry import TelemetryManager
from edgewalker.modules.cve_scan import scanner as cve
from edgewalker.modules.password_scan import scanner as pwd
from edgewalker.modules.port_scan import scanner as port


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_cve_search_errors(mock_search_async):
    # No product
    assert await cve.search_cves("") == []

    # Test error case
    mock_search_async.return_value = []
    assert await cve.search_cves("test", verbose=True) == []


@pytest.mark.asyncio
@patch("edgewalker.modules.cve_scan.scanner.search_cves_async")
async def test_cve_scan_edge_cases(mock_search):
    mock_search.return_value = [
        {"id": "CVE-1", "severity": "CRITICAL", "score": 9.8, "description": "X"}
    ]

    # No services with version
    hosts = [{"ip": "1.1.1.1", "mac": "00:00:00:00:00:00", "tcp": [{"port": 80, "name": "apache"}]}]
    res = await cve.scan(hosts, verbose=True)
    assert res.summary["total_services"] == 0

    # Multiple services
    hosts = [
        {
            "ip": "1.1.1.1",
            "mac": "00:00:00:00:00:00",
            "tcp": [
                {"port": 80, "name": "apache", "product_name": "apache", "product_version": "1.0"},
                {"port": 22, "name": "ssh", "product_name": "ssh", "product_version": "2.0"},
            ],
        }
    ]
    cb = MagicMock()
    res = await cve.scan(hosts, progress_callback=cb)
    assert res.summary["total_services"] == 2
    assert mock_search.called


# --- Password Scan Boost ---


def test_pwd_load_credentials_top_n():
    with patch(
        "edgewalker.modules.password_scan.scanner._cred_cache", {"ssh": [("a", "b"), ("c", "d")]}
    ):
        assert len(pwd.load_credentials("ssh", top_n=1)) == 1


@patch("socket.socket")
def test_pwd_check_port_open_error(mock_sock):
    mock_sock.return_value.connect_ex.side_effect = Exception("error")
    assert pwd.check_port_open("1.1.1.1", 80) is False


def test_pwd_suppress_stderr():
    with pwd.SuppressStderr():
        sys.stderr.write("test")
    # No assertion needed, just ensuring it runs


@pytest.mark.asyncio
@patch("asyncio.open_connection")
async def test_pwd_test_telnet_timeout(mock_open):
    mock_open.side_effect = asyncio.TimeoutError()
    assert await pwd.test_telnet("1.1.1.1", 23, "u", "p") is False


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.password_scan.scanner.AsyncServiceScanner.is_port_open",
    new_callable=AsyncMock,
)
@patch("edgewalker.modules.password_scan.scanner.SSHScanner.attempt_login", new_callable=AsyncMock)
@patch("edgewalker.modules.password_scan.scanner.load_credentials", return_value=[("u", "p")])
async def test_pwd_test_service_verbose(mock_load, mock_login, mock_port):
    mock_port.return_value = True
    mock_login.return_value = (True, False)
    cb = MagicMock()
    # _test_service(host, service, port, test_func, top_n, verbose, progress_callback)
    # Wait, I didn't change _test_service signature, but I changed AsyncServiceScanner.__init__
    # and PasswordScanner.scan_host.
    # Let's check _test_service in src/edgewalker/modules/password_scan/scanner.py
    res = await pwd._test_service("1.1.1.1", "ssh", 22, pwd.test_ssh, None, True, cb)
    assert res.login_attempt.value == "successful"
    assert cb.called


# --- Port Scan Boost ---


def test_port_validate_target():
    assert port.validate_target("") == "Target cannot be empty"
    assert port.validate_target("1.1.1.1") is None
    assert port.validate_target("1.1.1.0/24") is None
    assert port.validate_target("invalid/range") == "Invalid CIDR range: invalid/range"
    assert port.validate_target("host.name") is None
    assert (
        port.validate_target("invalid!target")
        == "Invalid target format: invalid!target (expected IP, CIDR range, or valid hostname)"
    )


@patch("edgewalker.modules.port_scan.scanner.check_nmap_permissions", return_value=False)
@patch("os.geteuid", return_value=1000)
def test_port_check_privileges(mock_get, mock_check):
    assert "requires root privileges" in port.check_privileges()


@pytest.mark.asyncio
@patch("asyncio.create_subprocess_exec")
async def test_port_scan_batch_error(mock_exec):
    mock_exec.side_effect = FileNotFoundError()
    with pytest.raises(FileNotFoundError):
        await port._scan_batch(["1.1.1.1"], "80", [], 10)


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner._scan_batch", new_callable=AsyncMock)
async def test_port_parallel_scan_verbose(mock_batch):
    mock_batch.return_value = ("xml", {"1.1.1.1"})
    cb = MagicMock()
    await port._parallel_scan(
        ["1.1.1.1", "1.1.1.2"], "80", [], 10, verbose=True, progress_callback=cb
    )
    assert mock_batch.called


@pytest.mark.asyncio
@patch("edgewalker.modules.port_scan.scanner.ping_sweep", new_callable=AsyncMock, return_value=[])
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_port_scan_no_hosts(mock_sudo, mock_ping):
    res = await port.scan("1.1.1.1", verbose=True)
    assert res.hosts_responded == 0


@pytest.mark.asyncio
@patch(
    "edgewalker.modules.port_scan.scanner.ping_sweep",
    new_callable=AsyncMock,
    return_value=["1.1.1.1"],
)
@patch("edgewalker.modules.port_scan.scanner._parallel_scan", new_callable=AsyncMock)
@patch("edgewalker.modules.port_scan.scanner.check_privileges", return_value=None)
async def test_port_scan_nmap_not_found(mock_sudo, mock_parallel, mock_ping):
    mock_parallel.side_effect = FileNotFoundError()
    res = await port.scan("1.1.1.1")
    assert "nmap not found" in res.error


# --- Utils Boost ---


@patch("edgewalker.utils.console.clear")
def test_utils_clear_screen(mock_clear):
    utils.clear_screen()
    assert mock_clear.called


@patch("edgewalker.utils.settings")
def test_utils_has_any_results(settings_mock):
    settings_mock.output_dir.exists.return_value = True
    settings_mock.output_dir.glob.return_value = [MagicMock()]
    assert utils.has_any_results() is True


# --- Telemetry Boost ---


def test_telemetry_telemetry_enabled(settings_mock):
    manager = TelemetryManager(settings_mock)
    settings_mock.telemetry_enabled = None
    assert manager.has_seen_telemetry_prompt() is False


@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_telemetry_submit(mock_post, settings_mock):
    manager = TelemetryManager(settings_mock)
    settings_mock.telemetry_enabled = False
    await manager.submit_scan_data("test", {"data": "x"})
    # Should not call post if not opted in
    assert not mock_post.called


# --- Risk Boost ---


def test_risk_calculate_score(settings_mock):
    # Test various risk factors
    port_data = {
        "hosts": [
            {
                "ip": "1.1.1.1",
                "mac": "00:00:00:00:00:00",
                "tcp": [{"port": 22, "name": "ssh"}, {"port": 21, "name": "ftp"}],
                "state": "up",
            }
        ]
    }
    cred_data = {
        "results": [
            {
                "ip": "1.1.1.1",
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
                "ip": "1.1.1.1",
                "port": 22,
                "service": "ssh",
                "product": "test",
                "version": "1.0",
                "cves": [
                    {"id": "CVE-1", "description": "test", "severity": "CRITICAL", "score": 9.8}
                ],
            }
        ]
    }

    with patch("edgewalker.core.risk.settings", settings_mock):
        engine = RiskEngine(port_data, cred_data, cve_data)
        res = engine.calculate_device_risk("1.1.1.1")
        assert res["score"] > 0

        level, color = RiskEngine.get_risk_level(res["score"])
        assert level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

        # Test network grade
        devices = [{"risk": res}]
        grade, reason, color = RiskEngine.calculate_network_grade(devices)
        assert grade == "F"


# Standard Library
