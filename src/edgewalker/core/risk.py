"""EdgeWalker Risk Engine — Security scoring and grading.

Calculates risk scores for individual devices and an overall security
grade for the network based on discovered vulnerabilities.
"""

from __future__ import annotations

# Standard Library
from typing import Any, Type, TypeVar

# Third Party
import yaml

# First Party
from edgewalker import theme
from edgewalker.core.config import settings
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel
from edgewalker.modules.sql_scan.models import SqlScanModel
from edgewalker.modules.web_scan.models import WebScanModel

T = TypeVar("T")


class RiskEngine:
    """Calculates security risk scores and network grades."""

    def __init__(
        self,
        port_data: PortScanModel | dict[str, Any],
        cred_data: PasswordScanModel | dict[str, Any],
        cve_data: CveScanModel | dict[str, Any],
        sql_data: SqlScanModel | dict[str, Any] | None = None,
        web_data: WebScanModel | dict[str, Any] | None = None,
        gateway_ip: str | None = None,
    ) -> None:
        """Initialize the risk engine with scan data."""
        # Convert dicts to models if they match the new format, otherwise keep as dict
        self.port_data = self._ensure_model(port_data, PortScanModel)
        self.cred_data = self._ensure_model(cred_data, PasswordScanModel)
        self.cve_data = self._ensure_model(cve_data, CveScanModel)
        self.sql_data = self._ensure_model(sql_data, SqlScanModel) if sql_data else None
        self.web_data = self._ensure_model(web_data, WebScanModel) if web_data else None
        self.gateway_ip = gateway_ip or getattr(self.port_data, "gateway_ip", None)

        # Load remediations
        self.remediations = self._load_remediations()

        # Index data by IP for performance (O(1) lookup)
        # Use string keys for compatibility with tests
        self._port_index: dict[str, Any] = {}
        hosts = getattr(self.port_data, "hosts", [])
        if not hosts and isinstance(self.port_data, dict):
            hosts = self.port_data.get("hosts", [])

        if isinstance(hosts, list):
            for h in hosts:
                ip = str(getattr(h, "ip", h.get("ip") if isinstance(h, dict) else ""))
                if ip:
                    self._port_index[ip] = h

        # Index credentials
        self._cred_index: dict[str, list[Any]] = {}
        results = getattr(self.cred_data, "results", [])
        if not results and isinstance(self.cred_data, dict):
            results = self.cred_data.get("results", [])
            if not results:
                hosts = self.cred_data.get("hosts", [])
                for h in hosts:
                    ip = h.get("host")
                    services = h.get("services", {})
                    for svc, details in services.items():
                        if details.get("status") == "vulnerable":
                            self._cred_index.setdefault(ip, []).append(svc)

        if isinstance(results, list):
            for item in results:
                # ... (rest of the loop)
                ip = str(getattr(item, "ip", item.get("ip") if isinstance(item, dict) else ""))
                login_attempt = getattr(
                    item,
                    "login_attempt",
                    item.get("login_attempt") if isinstance(item, dict) else "",
                )

                # Check for successful login
                is_success = str(login_attempt) in {"successful", "StatusEnum.successful"}
                if ip and is_success:
                    service = str(
                        getattr(
                            item, "service", item.get("service") if isinstance(item, dict) else ""
                        )
                    )
                    # Clean up enum string if present
                    if "." in service:
                        service = service.split(".")[-1]

                    creds = getattr(
                        item,
                        "credentials",
                        item.get("credentials") if isinstance(item, dict) else None,
                    )

                    if creds:
                        user = getattr(
                            creds, "user", creds.get("user") if isinstance(creds, dict) else ""
                        )
                        password = getattr(
                            creds,
                            "password",
                            creds.get("password") if isinstance(creds, dict) else "",
                        )
                        self._cred_index.setdefault(ip, []).append({
                            "service": service,
                            "user": user,
                            "password": password,
                        })
                    else:
                        # If no creds object but successful, just add the service name
                        self._cred_index.setdefault(ip, []).append(service)

        # Index SQL
        self._sql_index: dict[str, list[Any]] = {}
        if self.sql_data:
            sql_results = getattr(self.sql_data, "results", [])
            if not sql_results and isinstance(self.sql_data, dict):
                sql_results = self.sql_data.get("results", [])

            if isinstance(sql_results, list):
                for res in sql_results:
                    ip = str(getattr(res, "ip", res.get("ip") if isinstance(res, dict) else ""))
                    if ip:
                        self._sql_index.setdefault(ip, []).append(
                            res.model_dump() if hasattr(res, "model_dump") else res
                        )

        # Index Web
        self._web_index: dict[str, list[Any]] = {}
        if self.web_data:
            web_results = getattr(self.web_data, "results", [])
            if not web_results and isinstance(self.web_data, dict):
                web_results = self.web_data.get("results", [])

            if isinstance(web_results, list):
                for res in web_results:
                    ip = str(getattr(res, "ip", res.get("ip") if isinstance(res, dict) else ""))
                    if ip:
                        self._web_index.setdefault(ip, []).append(
                            res.model_dump() if hasattr(res, "model_dump") else res
                        )

        # Index CVEs
        self._cve_index: dict[str, list[Any]] = {}
        cve_results = getattr(self.cve_data, "results", [])
        if not cve_results and isinstance(self.cve_data, dict):
            cve_results = self.cve_data.get("results", [])
            # Legacy support for {"hosts": [{"ip": "...", "services": [{"cves": [...]}]}]}
            if not cve_results:
                hosts = self.cve_data.get("hosts", [])
                for h in hosts:
                    ip = h.get("ip")
                    services = h.get("services", [])
                    all_cves = []
                    for svc in services:
                        all_cves.extend(svc.get("cves", []))
                    if ip and all_cves:
                        self._cve_index[ip] = all_cves

        if isinstance(cve_results, list):
            for res in cve_results:
                ip = str(getattr(res, "ip", res.get("ip") if isinstance(res, dict) else ""))
                if ip:
                    cves = getattr(res, "cves", res.get("cves") if isinstance(res, dict) else [])
                    if isinstance(cves, list):
                        self._cve_index[ip] = [
                            c.model_dump() if hasattr(c, "model_dump") else c for c in cves
                        ]

    def _load_remediations(self) -> dict[str, Any]:
        """Load remediation database from YAML."""
        rem_file = settings.creds_file.parent / "remediation.yaml"
        if not rem_file.exists():
            return {}
        try:
            with open(rem_file, "r") as f:
                data = yaml.safe_load(f)
                return {r["id"]: r for r in data.get("remediations", [])}
        except Exception:
            return {}

    def _ensure_model(self, data: object, model_class: Type[T]) -> T | object:
        """Attempt to validate data against model_class, return raw data on failure."""
        if not isinstance(data, dict):
            return data
        try:
            # Use model_validate if it's a Pydantic model
            if hasattr(model_class, "model_validate"):
                return model_class.model_validate(data)
            return data
        except Exception:
            return data

    def calculate_device_risk(self, ip: str) -> dict[str, Any]:
        """Calculate a 0-100 risk score for a single device."""
        # 1. Exposure Score (Ports)
        exposure = self._calculate_exposure_score(ip)

        # 2. Credential Score
        credentials = self._calculate_credential_score(ip)

        # 3. Vulnerability Score (CVEs)
        vulnerabilities = self._calculate_vulnerability_score(ip)

        # 4. SQL Score
        sql_score = self._calculate_sql_score(ip)

        # 5. Web Score
        web_score = self._calculate_web_score(ip)

        # Weighted Average
        weights = settings.category_weights
        score = (
            (exposure * weights.get("exposure", 0.20))
            + (credentials * weights.get("credentials", 0.30))
            + (vulnerabilities * weights.get("vulnerabilities", 0.25))
            + (sql_score * weights.get("sql", 0.15))
            + (web_score * weights.get("web", 0.10))
        )

        # Gateway Prioritization: If this is the gateway, vulnerabilities are more critical
        is_gateway = str(ip) == str(self.gateway_ip)
        if is_gateway and score > 0:
            # Apply a 1.2x multiplier for gateway risk, capped at 100
            score = min(100, score * 1.2)
            # Ensure even low-risk gateways get some attention if they have any exposure
            score = max(score, 15)

        # Get details for the report
        host = self._port_index.get(ip)
        open_ports = []
        if host:
            # Handle both model and dict
            ports = getattr(
                host,
                "tcp",
                host.get("tcp") or host.get("tcp_ports", []) if isinstance(host, dict) else [],
            )
            if isinstance(ports, list):
                for p in ports:
                    p_num = getattr(p, "port", p.get("port") if isinstance(p, dict) else 0)
                    p_name = getattr(
                        p, "name", p.get("name") or p.get("service") if isinstance(p, dict) else ""
                    )
                    open_ports.append(f"{p_num}/{p_name}")
        # Get weak creds
        weak_creds = self._cred_index.get(ip, [])
        # Format weak_creds for display (extract service name if it's a dict)
        display_creds = []
        for c in weak_creds:
            if isinstance(c, dict):
                display_creds.append(c.get("service", "unknown"))
            else:
                display_creds.append(str(c))

        # Get CVEs
        cves = self._cve_index.get(ip, [])
        cve_list = [f"{c.get('id')} ({c.get('severity')})" for c in cves]

        # Map Remediations
        device_remediations = []
        if weak_creds:
            device_remediations.append(self.remediations.get("default_creds_ssh"))

        sql_results = self._sql_index.get(ip, [])
        for res in sql_results:
            if res.get("status") == "successful":
                device_remediations.append(self.remediations.get("default_creds_mysql"))
            elif res.get("status") == "anonymous":
                device_remediations.append(self.remediations.get("anonymous_redis"))

        web_results = self._web_index.get(ip, [])
        for res in web_results:
            if res.get("tls") and res["tls"].get("expired"):
                device_remediations.append(self.remediations.get("expired_tls_cert"))
            if res.get("sensitive_files"):
                device_remediations.append(self.remediations.get("sensitive_files_exposed"))
            if not res.get("headers", {}).get("csp") or not res.get("headers", {}).get("hsts"):
                device_remediations.append(self.remediations.get("missing_security_headers"))

        # Filter out None and duplicates
        device_remediations = [r for r in device_remediations if r]
        seen_rem = set()
        unique_remediations = []
        for r in device_remediations:
            if r["id"] not in seen_rem:
                unique_remediations.append(r)
                seen_rem.add(r["id"])

        # Get discovery info
        mdns_name = getattr(
            host, "mdns_name", host.get("mdns_name") if isinstance(host, dict) else None
        )
        upnp_info = getattr(
            host, "upnp_info", host.get("upnp_info") if isinstance(host, dict) else None
        )
        http_server = getattr(
            host, "http_server", host.get("http_server") if isinstance(host, dict) else None
        )
        http_title = getattr(
            host, "http_title", host.get("http_title") if isinstance(host, dict) else None
        )

        return {
            "score": int(min(100, score)),
            "risk_score": int(min(100, score)),  # Legacy name
            "risk_level": self.get_risk_level(score)[0],
            "is_gateway": is_gateway,
            "open_ports": open_ports,
            "weak_creds": display_creds,
            "raw_weak_creds": weak_creds,
            "cves": cve_list,
            "raw_cves": cves,
            "sql_findings": sql_results,
            "web_findings": web_results,
            "remediations": unique_remediations,
            "mdns_name": mdns_name,
            "upnp_info": upnp_info,
            "http_server": http_server,
            "http_title": http_title,
            "factors": {
                "exposure": exposure,
                "credentials": credentials,
                "vulnerabilities": vulnerabilities,
                "sql": sql_score,
                "web": web_score,
            },
        }

    def _calculate_exposure_score(self, ip: str) -> int:
        """Score based on open ports and their inherent risk."""
        host = self._port_index.get(ip)
        if not host:
            return 0

        ports = getattr(
            host,
            "tcp",
            host.get("tcp") or host.get("tcp_ports", []) if isinstance(host, dict) else [],
        )

        if not isinstance(ports, list) or not ports:
            return 0

        # Start with the highest severity port found
        max_sev = 0
        for p in ports:
            port_num = getattr(p, "port", p.get("port") if isinstance(p, dict) else 0)
            sev = settings.port_severity.get(port_num, settings.port_severity_default)
            if sev > max_sev:
                max_sev = sev

        # Add penalty for each additional open port
        extra = (len(ports) - 1) * settings.port_extra_penalty
        return min(100, max_sev + extra)

    def _calculate_credential_score(self, ip: str) -> int:
        """Score based on discovered default credentials."""
        vuln_services = self._cred_index.get(ip, [])

        if not vuln_services:
            return 0

        # Start with highest severity service
        max_sev = 0
        for svc in vuln_services:
            # Ensure svc is string for lookup
            if isinstance(svc, dict):
                svc_name = str(svc.get("service", "")).lower()
            else:
                svc_name = str(svc).lower()

            # Clean up enum string if present
            if "." in svc_name:
                svc_name = svc_name.split(".")[-1]

            sev = settings.cred_severity.get(svc_name, settings.cred_severity_default)
            if sev > max_sev:
                max_sev = sev

        # Add penalty for each additional vulnerable service
        extra = (len(vuln_services) - 1) * settings.cred_extra_penalty
        return min(100, max_sev + extra)

    def _calculate_sql_score(self, ip: str) -> int:
        """Score based on SQL vulnerabilities."""
        sql_results = self._sql_index.get(ip, [])
        if not sql_results:
            return 0

        max_sev = 0
        for res in sql_results:
            if res.get("status") in ["successful", "anonymous"]:
                svc = str(res.get("service", "")).lower()
                if "." in svc:
                    svc = svc.split(".")[-1]
                sev = settings.sql_severity.get(svc, settings.sql_severity_default)
                if sev > max_sev:
                    max_sev = sev

        return max_sev

    def _calculate_web_score(self, ip: str) -> int:
        """Score based on Web vulnerabilities."""
        web_results = self._web_index.get(ip, [])
        if not web_results:
            return 0

        score = 0
        for res in web_results:
            if res.get("tls") and res["tls"].get("expired"):
                score = max(score, settings.web_severity.get("expired_cert", 70))
            if res.get("sensitive_files"):
                score = max(score, settings.web_severity.get("sensitive_file", 90))
            if not res.get("headers", {}).get("csp") or not res.get("headers", {}).get("hsts"):
                score = max(score, settings.web_severity.get("missing_headers", 40))

        return min(100, score)

    def _calculate_vulnerability_score(self, ip: str) -> int:
        """Score based on known CVEs."""
        cves = self._cve_index.get(ip, [])

        if not cves:
            return 0

        # Start with highest severity CVE
        max_sev = 0
        for cve in cves:
            sev_label = cve.get("severity", "UNKNOWN").upper()
            sev = settings.cve_severity.get(sev_label, settings.cve_severity_default)
            if sev > max_sev:
                max_sev = sev

        # Add penalty for each additional CVE
        extra = (len(cves) - 1) * settings.cve_extra_penalty
        return min(100, max_sev + extra)

    @staticmethod
    def get_risk_level(score: float) -> tuple[str, str]:
        """Return (label, color) for a given risk score."""
        if score >= 80:
            return "CRITICAL", theme.RISK_CRITICAL
        if score >= 50:
            return "HIGH", theme.WARNING
        if score >= 25:
            return "MEDIUM", theme.ACCENT
        return ("LOW", theme.SUCCESS) if score > 0 else ("NONE", theme.MUTED)

    @staticmethod
    def calculate_network_grade(device_reports: list[dict[str, Any]]) -> tuple[str, str, str]:
        """Calculate an overall network grade (A-F)."""
        if not device_reports:
            return "A", "No devices found or scanned.", theme.SUCCESS

        # Check for critical vulnerabilities (instant F)
        # 1. Default credentials
        has_creds = any(d["risk"]["factors"].get("credentials", 0) > 0 for d in device_reports)
        # 2. Successful SQL login or anonymous access
        has_sql_vuln = any(d["risk"]["factors"].get("sql", 0) >= 80 for d in device_reports)
        # 3. Exposed sensitive files
        has_web_vuln = any(d["risk"]["factors"].get("web", 0) >= 90 for d in device_reports)

        if has_creds or has_sql_vuln or has_web_vuln:
            # Check if it's the gateway
            gateway_critical = any(
                (
                    d["risk"]["factors"].get("credentials", 0) > 0
                    or d["risk"]["factors"].get("sql", 0) >= 80
                    or d["risk"]["factors"].get("web", 0) >= 90
                )
                and d["risk"].get("is_gateway")
                for d in device_reports
            )
            if gateway_critical:
                return (
                    "F",
                    "CRITICAL: Severe vulnerabilities found on your GATEWAY. "
                    "Your entire network is at extreme risk.",
                    theme.RISK_CRITICAL,
                )

            reason = "Critical vulnerabilities found. Your network is trivially compromisable."
            if has_creds:
                reason = "Default credentials found. Your network is at high risk."
            elif has_sql_vuln:
                reason = "Unsecured database services found. Your data is at risk."
            elif has_web_vuln:
                reason = "Sensitive files or insecure web services found."

            return ("F", reason, theme.RISK_CRITICAL)

        # Get worst device score
        max_score = max(d["risk"]["score"] for d in device_reports)

        # Check if the worst score is the gateway
        gateway_report = next((d for d in device_reports if d["risk"].get("is_gateway")), None)
        gateway_score = gateway_report["risk"]["score"] if gateway_report else 0

        if gateway_score >= 80:
            return (
                "F",
                "CRITICAL: Your gateway has severe vulnerabilities. "
                "The perimeter of your network is compromised.",
                theme.RISK_CRITICAL,
            )

        if max_score >= 80:
            return "D", "Critical vulnerabilities found on your network.", theme.RISK_CRITICAL
        if max_score >= 50:
            return "C", "High risk devices present on your network.", theme.WARNING
        if max_score >= 25:
            return "B", "Medium risk devices found. Improvements recommended.", theme.ACCENT
        if max_score > 0:
            return "A", "Your network appears secure. No major issues found.", theme.SUCCESS

        return "A+", "Your network is perfectly secure. No issues found.", theme.SUCCESS
