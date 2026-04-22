"""EdgeWalker Display — Rich terminal renderable builders.

Constructs panels, tables, and reports for the CLI and TUI using the Rich library.
"""

from __future__ import annotations

# Standard Library
from datetime import datetime
from typing import Any

# Third Party
from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# First Party
from edgewalker import theme
from edgewalker.core.config import settings
from edgewalker.core.risk import RiskEngine
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel


def build_port_scan_display(results: dict[str, Any]) -> list[RenderableType]:
    """Build Rich renderables for port scan results."""
    renderables = []

    hosts = results.get("hosts", [])
    if not hosts:
        renderables.append(
            Panel(
                f"[{theme.WARNING}]No live hosts discovered on the network.[/{theme.WARNING}]",
                border_style=theme.WARNING,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        return renderables

    # Summary table
    table = Table(box=box.SIMPLE, header_style=f"bold {theme.HEADER}", width=theme.get_ui_width())
    table.add_column("IP Address", style=theme.PRIMARY)
    table.add_column("Vendor", style=theme.SECONDARY)
    table.add_column("Open Ports", justify="right")
    table.add_column("OS Match", style=theme.MUTED_STYLE)

    for host in hosts:
        ip = host.get("ip", "Unknown")
        vendor = host.get("vendor", "Unknown")
        ports = host.get("tcp") or host.get("tcp_ports") or []
        os_list = host.get("os") or host.get("os_matches") or []
        # Handle both list of strings and list of dicts
        if os_list and isinstance(os_list[0], dict):
            os_str = os_list[0].get("name", "Unknown")
        else:
            os_str = os_list[0] if os_list else "Unknown"

        table.add_row(ip, vendor, str(len(ports)), os_str)

    renderables.append(
        Panel(
            table,
            title=f"[{theme.HEADER}]PORT SCAN RESULTS[/{theme.HEADER}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
            width=theme.get_ui_width(),
        )
    )
    return renderables


def build_credential_display(results: dict[str, Any]) -> list[RenderableType]:
    """Build Rich renderables for credential scan results."""
    renderables = []

    # Handle both model-dumped dict and legacy dict
    items = results.get("results")
    if items is None:
        # Legacy format
        hosts = results.get("hosts", [])
        items = []
        for h in hosts:
            ip = h.get("host")
            for svc, data in h.get("services", {}).items():
                if data.get("status") == "vulnerable":
                    creds = data.get("credentials", [])
                    items.extend(
                        {
                            "ip": ip,
                            "service": svc,
                            "login_attempt": "successful",
                            "credentials": c,
                        }
                        for c in creds
                    )
    if not items:
        renderables.append(
            Panel(
                f"[{theme.SUCCESS}]No default credentials found. "
                f"All tested services are secure.[/{theme.SUCCESS}]",
                title=f"[{theme.SUCCESS}]CREDENTIAL SCAN[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        return renderables

    # Vulnerabilities table
    table = Table(
        box=box.SIMPLE, header_style=f"bold {theme.RISK_CRITICAL}", width=theme.get_ui_width()
    )
    table.add_column("IP Address", style=theme.PRIMARY)
    table.add_column("Service", style=theme.SECONDARY)
    table.add_column("Credentials", style=theme.WARNING)

    found = False
    for item in items:
        if item.get("login_attempt") in ["successful", "successful"]:
            found = True
            ip = item.get("ip")
            svc = item.get("service", "").upper()
            creds = item.get("credentials", {})
            user = creds.get("user") or creds.get("username", "unknown")
            pw = creds.get("password", "")
            table.add_row(ip, svc, f"{user}:{pw}")

    if found:
        renderables.append(
            Panel(
                table,
                title=f"[{theme.RISK_CRITICAL}]DEFAULT CREDENTIALS FOUND[/{theme.RISK_CRITICAL}]",
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
    else:
        renderables.append(
            Panel(
                f"[{theme.SUCCESS}]No default credentials found.[/{theme.SUCCESS}]",
                title=f"[{theme.SUCCESS}]CREDENTIAL SCAN[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    return renderables


def build_cve_display(results: dict[str, Any]) -> list[RenderableType]:
    """Build Rich renderables for CVE scan results."""
    renderables = []

    items = results.get("results", [])
    if not items:
        renderables.append(
            Panel(
                f"[{theme.SUCCESS}]No known CVEs found for discovered software.[/{theme.SUCCESS}]",
                title=f"[{theme.SUCCESS}]CVE SCAN[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        return renderables

    # CVE table
    table = Table(box=box.SIMPLE, header_style=f"bold {theme.HEADER}", width=theme.get_ui_width())
    table.add_column("IP Address", style=theme.PRIMARY)
    table.add_column("Service", style=theme.SECONDARY)
    table.add_column("CVE ID", style=theme.WARNING)
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="right")

    total_cves = 0
    for item in items:
        ip = item.get("ip")
        svc = f"{item.get('product')} {item.get('version')}"
        cves = item.get("cves", [])
        total_cves += len(cves)

        for cve in cves:
            sev = cve.get("severity", "UNKNOWN")
            color = theme.RISK_CRITICAL if sev == "CRITICAL" else theme.WARNING
            table.add_row(
                ip,
                svc,
                cve.get("id"),
                f"[{color}]{sev}[/{color}]",
                f"{cve.get('score'):.1f}",
            )

    if total_cves > 0:
        renderables.append(
            Panel(
                table,
                title=f"[{theme.RISK_CRITICAL}]VULNERABILITIES FOUND[/{theme.RISK_CRITICAL}]",
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
    else:
        renderables.append(
            Panel(
                f"[{theme.SUCCESS}]No known CVEs found.[/{theme.SUCCESS}]",
                title=f"[{theme.SUCCESS}]CVE SCAN[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    return renderables


def build_device_report(device_data: dict[str, Any]) -> RenderableType:
    """Build a detailed Rich report for a single device."""
    ip = device_data.get("ip", "Unknown")
    vendor = device_data.get("vendor", "Unknown")
    risk = device_data.get("risk", {})
    score = risk.get("score", 0)
    level, color = RiskEngine.get_risk_level(score)

    # Header Panel
    header_table = Table.grid(expand=True)
    header_table.add_column(style="bold")
    header_table.add_column(justify="right")

    header_table.add_row(
        Text(f"DEVICE: {ip} ({vendor})", style=theme.HEADER),
        Text(f"RISK: {level} ({score}/100)", style=f"bold {color}"),
    )

    sections = [Panel(header_table, border_style=color, box=box.ROUNDED)]

    # 1. Exposure (Ports)
    ports = risk.get("open_ports", [])
    port_text = Text()
    if ports:
        for p in ports:
            port_text.append(f" {theme.ICON_STEP} {p}\n", style=theme.WARNING)
    else:
        port_text.append(" No open ports discovered.", style=theme.MUTED)

    sections.append(
        Panel(
            port_text,
            title=f"[{theme.ACCENT}]OPEN PORTS[/{theme.ACCENT}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
        )
    )

    # 2. Credentials
    creds = risk.get("weak_creds", [])
    cred_text = Text()
    if creds:
        for c in creds:
            cred_text.append(f" {theme.ICON_ALERT} VULNERABLE: {c}\n", style=theme.RISK_CRITICAL)
    else:
        cred_text.append(" No default credentials found.", style=theme.SUCCESS)

    sections.append(
        Panel(
            cred_text,
            title=f"[{theme.ACCENT}]CREDENTIAL STATUS[/{theme.ACCENT}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
        )
    )

    # 3. Vulnerabilities (CVEs)
    cves = risk.get("cves", [])
    cve_text = Text()
    if cves:
        for c in cves:
            cve_text.append(f" {theme.ICON_FAIL} {c}\n", style=theme.RISK_CRITICAL)
    else:
        cve_text.append(" No known vulnerabilities found.", style=theme.SUCCESS)

    sections.append(
        Panel(
            cve_text,
            title=f"[{theme.ACCENT}]KNOWN VULNERABILITIES[/{theme.ACCENT}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
        )
    )

    # 4. SQL Findings
    sql_findings = risk.get("sql_findings", [])
    sql_text = Text()
    if sql_findings:
        for res in sql_findings:
            status_raw = res.get("status", "unknown").upper()
            if status_raw in ["SUCCESSFUL", "ANONYMOUS"]:
                status_text = status_raw
                color = theme.RISK_CRITICAL
            elif status_raw == "FAILED":
                status_text = "SECURE"
                color = theme.SUCCESS
            else:
                status_text = status_raw
                color = theme.WARNING

            sql_text.append(f" {theme.ICON_STEP} {res.get('service').upper()}: ", style=theme.TEXT)
            sql_text.append(f"{status_text}\n", style=f"bold {color}")
            if res.get("version"):
                sql_text.append(f"    Version: {res['version']}\n", style=theme.MUTED)
    else:
        sql_text.append(" No SQL services audited.", style=theme.MUTED)

    sections.append(
        Panel(
            sql_text,
            title=f"[{theme.ACCENT}]SQL AUDIT[/{theme.ACCENT}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
        )
    )

    # 5. Web Findings
    web_findings = risk.get("web_findings", [])
    web_text = Text()
    if web_findings:
        for res in web_findings:
            web_text.append(
                f" {theme.ICON_STEP} {res.get('protocol').upper()}:{res.get('port')}\n",
                style=theme.TEXT,
            )
            if res.get("tls") and res["tls"].get("expired"):
                web_text.append(
                    f"    {theme.ICON_ALERT} Expired SSL Certificate\n",
                    style=f"bold {theme.RISK_CRITICAL}",
                )
            if res.get("sensitive_files"):
                web_text.append(
                    f"    {theme.ICON_ALERT} Exposed Files: {', '.join(res['sensitive_files'])}\n",
                    style=f"bold {theme.RISK_CRITICAL}",
                )

            # Headers
            h = res.get("headers", {})
            missing = []
            if not h.get("csp"):
                missing.append("CSP")
            if not h.get("hsts"):
                missing.append("HSTS")
            if missing:
                web_text.append(
                    f"    {theme.ICON_WARN} Missing Headers: {', '.join(missing)}\n",
                    style=theme.WARNING,
                )
    else:
        web_text.append(" No web services audited.", style=theme.MUTED)

    sections.append(
        Panel(
            web_text,
            title=f"[{theme.ACCENT}]WEB AUDIT[/{theme.ACCENT}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
        )
    )

    # Discovery Info
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style=theme.MUTED)
    info_table.add_column()

    if mdns := risk.get("mdns_name"):
        info_table.add_row("mDNS Name:", mdns)
    if server := risk.get("http_server"):
        info_table.add_row("HTTP Server:", server)
    if title := risk.get("http_title"):
        info_table.add_row("HTTP Title:", title)

    if info_table.row_count > 0:
        sections.append(
            Panel(
                info_table,
                title=f"[{theme.ACCENT}]DISCOVERY INFO[/{theme.ACCENT}]",
                border_style=theme.ACCENT,
                box=theme.BOX_STYLE,
            )
        )

    # 6. Remediations
    remediations = risk.get("remediations", [])
    if remediations:
        rem_text = Text()
        for rem in remediations:
            rem_text.append(f" {theme.ICON_CHECK} {rem['title']}\n", style=f"bold {theme.SUCCESS}")
            # Indent the remediation steps
            steps = rem["remediation"].strip().split("\n")
            for step in steps:
                rem_text.append(f"    {step}\n", style=theme.TEXT)
            rem_text.append("\n")

        sections.append(
            Panel(
                rem_text,
                title=f"[{theme.SUCCESS}]RECOMMENDED REMEDIATIONS[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
            )
        )

    return Group(*sections)


def build_risk_report(
    port_data: dict[str, Any],
    cred_data: dict[str, Any],
    cve_data: dict[str, Any],
    sql_data: dict[str, Any] | None = None,
    web_data: dict[str, Any] | None = None,
) -> tuple[list[RenderableType], dict[str, Any]]:
    """Build the comprehensive security risk report."""
    # Convert to Pydantic models if they are dicts
    if isinstance(port_data, dict):
        port_model = PortScanModel(**port_data)
    else:
        port_model = port_data

    if isinstance(cred_data, dict):
        # Ensure results exists for PasswordScanModel
        if "results" not in cred_data:
            cred_data["results"] = []
        cred_model = PasswordScanModel(**cred_data)
    else:
        cred_model = cred_data

    if isinstance(cve_data, dict):
        # Ensure results exists for CveScanModel
        if "results" not in cve_data:
            cve_data["results"] = []
        cve_model = CveScanModel(**cve_data)
    else:
        cve_model = cve_data

    engine = RiskEngine(port_model, cred_model, cve_model, sql_data, web_data)
    renderables = []

    hosts = [h for h in port_model.hosts if h.state == "up"]
    if not hosts:
        renderables.append(
            Panel(
                f"[{theme.WARNING}]No devices found to assess.[/{theme.WARNING}]",
                border_style=theme.WARNING,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )
        return renderables, {}

    device_reports = []

    for host in hosts:
        ip = str(host.ip)
        if not ip:
            continue
        risk = engine.calculate_device_risk(ip)
        device_reports.append({"ip": ip, "vendor": host.vendor, "risk": risk})

    # Sort by risk score descending
    device_reports.sort(key=lambda x: x["risk"]["score"], reverse=True)

    # Calculate stats for the display
    total_devices = len(device_reports)
    vulnerable_devices = len([d for d in device_reports if d["risk"]["score"] > 0])
    default_creds = sum(d["risk"]["factors"]["credentials"] > 0 for d in device_reports)
    sql_vulns = sum(d["risk"]["factors"]["sql"] > 0 for d in device_reports)
    web_vulns = sum(d["risk"]["factors"]["web"] > 0 for d in device_reports)
    total_cves = sum(len(d["risk"]["cves"]) for d in device_reports)
    total_ports = sum(len(d["risk"]["open_ports"]) for d in device_reports)

    # Network Grade Panel
    grade, reason, color = RiskEngine.calculate_network_grade(device_reports)

    # Stats list (Left side)
    stats_text = Text()
    stats_text.append(f"  {theme.ICON_SCAN} Total Devices Scanned: ", style=theme.TEXT)
    stats_text.append(f"{total_devices}\n", style=f"bold {theme.PRIMARY}")

    stats_text.append(f"  {theme.ICON_VULN} Vulnerable Devices: ", style=theme.TEXT)
    stats_text.append(
        f"{vulnerable_devices}\n",
        style=f"bold {theme.RISK_CRITICAL if vulnerable_devices > 0 else theme.SUCCESS}",
    )

    stats_text.append(f"  {theme.ICON_SKULL} Default Credentials: ", style=theme.TEXT)
    stats_text.append(
        f"{default_creds}\n",
        style=f"bold {theme.RISK_CRITICAL if default_creds > 0 else theme.SUCCESS}",
    )

    stats_text.append(f"  {theme.ICON_STEP} SQL Vulnerabilities: ", style=theme.TEXT)
    stats_text.append(
        f"{sql_vulns}\n",
        style=f"bold {theme.RISK_CRITICAL if sql_vulns > 0 else theme.SUCCESS}",
    )

    stats_text.append(f"  {theme.ICON_STEP} Web Vulnerabilities: ", style=theme.TEXT)
    stats_text.append(
        f"{web_vulns}\n",
        style=f"bold {theme.RISK_CRITICAL if web_vulns > 0 else theme.SUCCESS}",
    )

    stats_text.append(f"  {theme.ICON_WARN} Known CVEs Found: ", style=theme.TEXT)
    stats_text.append(
        f"{total_cves}\n", style=f"bold {theme.WARNING if total_cves > 0 else theme.SUCCESS}"
    )

    stats_text.append(f"  {theme.ICON_CIRCLE} Open Ports Exposed: ", style=theme.TEXT)
    stats_text.append(f"{total_ports}\n", style=f"bold {theme.ACCENT}")

    # ASCII Grade (Right side)
    grade_art = theme.grade_art(grade, color)

    # Layout: Stats on left, Grade on right
    grade_display = Columns([stats_text, grade_art], expand=True, padding=(0, 4))

    renderables.append(
        Panel(
            Group(Text("\n"), grade_display, Text(f"\n  {reason}\n", style=theme.TEXT)),
            title=f"[{theme.HEADER}]NETWORK SECURITY GRADE[/{theme.HEADER}]",
            border_style=color,
            box=theme.BOX_STYLE,
            width=theme.get_ui_width(),
        )
    )

    # Device Risk Table
    table = Table(box=box.SIMPLE, header_style=f"bold {theme.HEADER}", width=theme.get_ui_width())
    table.add_column("Device", style=theme.PRIMARY)
    table.add_column("Risk Level", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Top Issues", style=theme.MUTED_STYLE)

    for dev in device_reports:
        ip = dev["ip"]
        vendor = dev["vendor"]
        risk = dev["risk"]

        # Use discovery info for better naming
        display_name = vendor
        if risk.get("mdns_name"):
            display_name = f"{risk['mdns_name']} ({vendor})"
        elif risk.get("upnp_info") and risk["upnp_info"].get("modelName"):
            display_name = f"{risk['upnp_info']['modelName']} ({vendor})"

        level, l_color = RiskEngine.get_risk_level(risk["score"])

        issues = []
        if risk["factors"]["credentials"] > 0:
            issues.append(f"[{theme.RISK_CRITICAL}]Default Creds[/{theme.RISK_CRITICAL}]")
        if risk["factors"]["sql"] > 0:
            issues.append(f"[{theme.RISK_CRITICAL}]SQL Vuln[/{theme.RISK_CRITICAL}]")
        if risk["factors"]["web"] > 0:
            issues.append(f"[{theme.RISK_CRITICAL}]Web Vuln[/{theme.RISK_CRITICAL}]")
        if risk["factors"]["vulnerabilities"] > 0:
            issues.append(f"[{theme.WARNING}]Known CVEs[/{theme.WARNING}]")
        if risk["factors"]["exposure"] > 50:
            issues.append("High Exposure")

        issue_str = ", ".join(issues) if issues else "None detected"

        table.add_row(
            f"{display_name}\n[dim]{ip}[/dim]",
            f"[{l_color}]{level}[/{l_color}]",
            f"{risk['score']}",
            issue_str,
        )

    renderables.append(
        Panel(
            table,
            title=f"[{theme.HEADER}]DEVICE RISK ASSESSMENT[/{theme.HEADER}]",
            border_style=theme.ACCENT,
            box=theme.BOX_STYLE,
            width=theme.get_ui_width(),
        )
    )

    # Detailed Vulnerability Lists
    all_creds = []
    all_cves = []
    all_sql = []
    all_web = []
    all_remediations = {}  # Use dict to deduplicate by ID
    for dev in device_reports:
        ip = dev["ip"]
        risk = dev["risk"]
        for cred in risk.get("raw_weak_creds", []):
            if isinstance(cred, dict):
                all_creds.append({"ip": ip, **cred})
            else:
                all_creds.append({
                    "ip": ip,
                    "service": str(cred),
                    "user": "unknown",
                    "password": "unknown",
                })
        all_cves.extend({"ip": ip, **cve} for cve in risk.get("raw_cves", []))
        all_sql.extend({"ip": ip, **sql} for sql in risk.get("sql_findings", []))
        all_web.extend({"ip": ip, **web} for web in risk.get("web_findings", []))

        for rem in risk.get("remediations", []):
            if rem["id"] not in all_remediations:
                all_remediations[rem["id"]] = rem

    if all_creds:
        cred_table = Table(
            box=box.SIMPLE, header_style=f"bold {theme.RISK_CRITICAL}", width=theme.get_ui_width()
        )
        cred_table.add_column("IP Address", style=theme.PRIMARY)
        cred_table.add_column("Service", style=theme.SECONDARY)
        cred_table.add_column("Credentials", style=theme.WARNING)

        for cred in all_creds:
            cred_table.add_row(
                cred["ip"], cred["service"].upper(), f"{cred['user']}:{cred['password']}"
            )

        renderables.append(
            Panel(
                cred_table,
                title=f"[{theme.RISK_CRITICAL}]VULNERABLE CREDENTIALS[/{theme.RISK_CRITICAL}]",
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    if all_sql:
        sql_table = Table(
            box=box.SIMPLE, header_style=f"bold {theme.RISK_CRITICAL}", width=theme.get_ui_width()
        )
        sql_table.add_column("IP Address", style=theme.PRIMARY)
        sql_table.add_column("Service", style=theme.SECONDARY)
        sql_table.add_column("Status", style=theme.WARNING)
        sql_table.add_column("Details", style=theme.MUTED_STYLE)

        for sql in all_sql:
            status_raw = sql.get("status", "unknown").upper()
            if status_raw in ["SUCCESSFUL", "ANONYMOUS"]:
                status_text = status_raw
                color = theme.RISK_CRITICAL
            elif status_raw == "FAILED":
                status_text = "SECURE"
                color = theme.SUCCESS
            else:
                status_text = status_raw
                color = theme.WARNING

            details = f"Version: {sql.get('version') or 'Unknown'}"
            if sql.get("databases"):
                details += f" | DBs: {len(sql['databases'])}"

            sql_table.add_row(
                sql["ip"], sql["service"].upper(), f"[{color}]{status_text}[/{color}]", details
            )

        renderables.append(
            Panel(
                sql_table,
                title=f"[{theme.RISK_CRITICAL}]SQL VULNERABILITIES[/{theme.RISK_CRITICAL}]",
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    if all_web:
        web_table = Table(
            box=box.SIMPLE, header_style=f"bold {theme.HEADER}", width=theme.get_ui_width()
        )
        web_table.add_column("IP Address", style=theme.PRIMARY)
        web_table.add_column("Service", style=theme.SECONDARY)
        web_table.add_column("Issues", style=theme.WARNING)

        for web in all_web:
            issues = []
            if web.get("tls") and web["tls"].get("expired"):
                issues.append("Expired SSL")
            if web.get("sensitive_files"):
                issues.append(f"Exposed Files ({len(web['sensitive_files'])})")
            if not web.get("headers", {}).get("csp") or not web.get("headers", {}).get("hsts"):
                issues.append("Missing Headers")

            if issues:
                web_table.add_row(
                    web["ip"], f"{web['protocol'].upper()}:{web['port']}", ", ".join(issues)
                )

        if web_table.row_count > 0:
            renderables.append(
                Panel(
                    web_table,
                    title=f"[{theme.RISK_CRITICAL}]WEB VULNERABILITIES[/{theme.RISK_CRITICAL}]",
                    border_style=theme.RISK_CRITICAL,
                    box=theme.BOX_STYLE,
                    width=theme.get_ui_width(),
                )
            )

    if all_cves:
        cve_table = Table(
            box=box.SIMPLE, header_style=f"bold {theme.HEADER}", width=theme.get_ui_width()
        )
        cve_table.add_column("IP Address", style=theme.PRIMARY)
        cve_table.add_column("CVE ID", style=theme.WARNING)
        cve_table.add_column("Severity", justify="center")
        cve_table.add_column("Score", justify="right")

        for cve in all_cves:
            sev = cve.get("severity", "UNKNOWN")
            color = theme.RISK_CRITICAL if sev == "CRITICAL" else theme.WARNING
            cve_table.add_row(
                cve["ip"],
                cve.get("id"),
                f"[{color}]{sev}[/{color}]",
                f"{cve.get('score'):.1f}",
            )

        renderables.append(
            Panel(
                cve_table,
                title=(
                    f"[{theme.RISK_CRITICAL}]KNOWN VULNERABILITIES (CVEs)[/{theme.RISK_CRITICAL}]"
                ),
                border_style=theme.RISK_CRITICAL,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    if all_remediations:
        rem_text = Text()
        for rem in all_remediations.values():
            rem_text.append(f" {theme.ICON_CHECK} {rem['title']}\n", style=f"bold {theme.SUCCESS}")
            steps = rem["remediation"].strip().split("\n")
            for step in steps:
                rem_text.append(f"    {step}\n", style=theme.TEXT)
            rem_text.append("\n")

        renderables.append(
            Panel(
                rem_text,
                title=f"[{theme.SUCCESS}]RECOMMENDED REMEDIATIONS[/{theme.SUCCESS}]",
                border_style=theme.SUCCESS,
                box=theme.BOX_STYLE,
                width=theme.get_ui_width(),
            )
        )

    # Summary data for JSON export
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "network_grade": grade,
        "grade_reason": reason,
        "summary": {
            "total_devices": len(device_reports),
            "critical_devices": len([d for d in device_reports if d["risk"]["score"] >= 80]),
            "high_devices": len([d for d in device_reports if 50 <= d["risk"]["score"] < 80]),
            "medium_devices": len([d for d in device_reports if 25 <= d["risk"]["score"] < 50]),
            "devices_with_default_creds": len([
                d for d in device_reports if d["risk"]["factors"]["credentials"] > 0
            ]),
        },
        "devices": device_reports,
    }

    return renderables, report_data


def build_mode_panel() -> Panel:
    """Build the mode selection panel for the interactive menu."""
    text = Text()
    text.append("  [1] ", style=theme.ACCENT)
    text.append("Guided Assessment ", style=theme.HEADER)
    text.append("(Recommended)\n", style=theme.MUTED_STYLE)
    text.append("      Sequentially run all scans and generate a report\n\n", style=theme.TEXT)

    text.append("  [2] ", style=theme.ACCENT)
    text.append("Manual Mode\n", style=theme.HEADER)
    text.append("      Run individual scans and browse results\n\n", style=theme.TEXT)

    if (settings.output_dir / "security_report.json").exists():
        text.append("  [3] ", style=theme.ACCENT)
        text.append("View Last Report\n", style=theme.HEADER)
        text.append("      Display the last generated security assessment\n\n", style=theme.TEXT)

    text.append("  [4] ", style=theme.ACCENT)
    text.append("Settings\n", style=theme.HEADER)
    text.append("      Manage EdgeWalker configuration\n\n", style=theme.TEXT)

    text.append("  [0] ", style=theme.ACCENT)
    text.append("Exit", style=theme.HEADER)

    return Panel(
        text,
        title="SELECT MODE",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
        width=theme.get_ui_width(),
    )


def build_status_panel() -> Panel:
    """Build the status panel for manual mode."""
    # First Party
    from edgewalker.utils import get_scan_status  # noqa: PLC0415

    status = get_scan_status()

    text = Text()

    if not status["port_scan"]:
        text.append("  NO PORT SCAN DATA\n", style=theme.WARNING)
        text.append("  Run a scan to begin assessment.\n", style=theme.MUTED_STYLE)
    elif not status["password_scan"] or not status["cve_scan"]:
        text.append("  QUICK SCAN COMPLETE\n", style=theme.SUCCESS)
        text.append(
            f"  {status['devices_found']} devices found. Run more tests.\n", style=theme.TEXT
        )
    else:
        text.append("  VULNERABILITIES FOUND\n", style=theme.RISK_CRITICAL)
        text.append(
            f"  Assessment complete for {status['devices_found']} devices.\n", style=theme.TEXT
        )

    text.append("\n  OPTIONS\n\n", style=theme.HEADER)
    text.append("    [1] View Risk Assessment (Report)\n", style=theme.TEXT)
    text.append("    [2] Run Quick Port Scan\n", style=theme.TEXT)
    text.append("    [3] Run Full Port Scan\n", style=theme.TEXT)
    text.append("    [4] Run Password Test\n", style=theme.TEXT)
    text.append("    [5] Run CVE Check\n", style=theme.TEXT)
    text.append("    [6] Run SQL Audit\n", style=theme.TEXT)
    text.append("    [7] Run Web Audit\n", style=theme.TEXT)
    text.append("    [8] Browse Raw Results\n", style=theme.TEXT)
    text.append("    [9] Clear All Results\n", style=theme.TEXT)
    text.append("\n    [0] Back to Main Menu", style=theme.TEXT)

    return Panel(
        text,
        title="MANUAL MODE",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
        width=theme.get_ui_width(),
    )


def build_telemetry_panel() -> Panel:
    """Build the telemetry notification panel."""
    text = Text()
    text.append("  EdgeWalker collects anonymous usage data by default to\n", style=theme.TEXT)
    text.append("  help us improve the tool and identify emerging IoT\n", style=theme.TEXT)
    text.append("  vulnerabilities. This data is vital for our research.\n\n", style=theme.TEXT)

    text.append("  PRIVACY FIRST:\n", style=f"bold {theme.SECONDARY}")
    text.append(
        f"  {theme.ICON_BULLET} We NEVER share your IP address or hostnames\n", style=theme.TEXT
    )
    text.append(f"  {theme.ICON_BULLET} We NEVER share your full MAC addresses\n", style=theme.TEXT)
    text.append(
        f"  {theme.ICON_BULLET} All data is anonymized before leaving your machine\n\n",
        style=theme.TEXT,
    )

    text.append("  LEARN MORE & OPT-OUT:\n", style=f"bold {theme.SECONDARY}")
    text.append("  Read our full data privacy policy and see what we collect:\n", style=theme.TEXT)
    text.append("  https://docs.periphery.security/edgewalker/data-privacy\n\n", style=theme.ACCENT)
    text.append("  To opt-out, run: ", style=theme.TEXT)
    text.append("edgewalker config set telemetry_enabled false", style=f"bold {theme.PRIMARY}")

    return Panel(
        text,
        title="ANONYMOUS TELEMETRY",
        border_style=theme.SECONDARY,
        box=theme.BOX_STYLE,
        width=theme.get_ui_width(),
    )


def build_scan_type_panel() -> Panel:
    """Build the scan type selection panel."""
    text = Text()
    text.append("  [1] ", style=theme.ACCENT)
    text.append("Quick Scan ", style=theme.HEADER)
    text.append("(~30 seconds)\n", style=theme.MUTED_STYLE)
    text.append("      Scans 28 common IoT ports (SSH, Telnet, RTSP, etc.)\n\n", style=theme.TEXT)

    text.append("  [2] ", style=theme.ACCENT)
    text.append("Full Scan ", style=theme.HEADER)
    text.append("(~15 minutes)\n", style=theme.MUTED_STYLE)
    text.append("      Scans ALL 65535 ports on every discovered device\n", style=theme.TEXT)

    return Panel(
        text,
        title="SELECT SCAN TYPE",
        border_style=theme.ACCENT,
        box=theme.BOX_STYLE,
        width=theme.get_ui_width(),
    )
