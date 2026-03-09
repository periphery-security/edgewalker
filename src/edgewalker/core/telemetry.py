"""EdgeWalker Telemetry — Anonymous data sharing and opt-in management.

Handles user consent, data anonymization, and submission of scan
results to the Periphery research API.
"""

# Standard Library
import asyncio
import hashlib
import json
import re
import time
import uuid
from typing import Any, Optional

# Third Party
import httpx
from loguru import logger

# First Party
from edgewalker.core.config import Settings, save_settings


class TelemetryManager:
    """Manages anonymous data sharing and user consent."""

    def __init__(self, settings: Settings) -> None:
        """Initialize the telemetry manager with settings."""
        self.settings = settings

    def get_session_id(self) -> str:
        """Get or create a persistent session ID for this user."""
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        session_file = self.settings.output_dir / "session_id"

        if session_file.exists():
            return session_file.read_text().strip()

        # Generate new session ID (32 char hex string)
        session_id = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
        session_file.write_text(session_id)
        return session_id

    def is_telemetry_enabled(self) -> bool:
        """Check if user has opted in to data sharing."""
        if self.settings.telemetry_enabled is not None:
            return self.settings.telemetry_enabled

        # Fallback/Migration: Check legacy file
        optin_file = self.settings.output_dir / "optin"
        if optin_file.exists():
            try:
                opted_in = optin_file.read_text().strip() == "yes"
                self.set_telemetry_status(opted_in)  # Migrate to config
                optin_file.unlink()  # Remove legacy file
                return opted_in
            except Exception as e:
                logger.error(f"Failed to migrate legacy optin file: {e}")

        return False

    def set_telemetry_status(self, opted_in: bool) -> None:
        """Save user's opt-in preference to config."""
        self.settings.telemetry_enabled = opted_in
        save_settings(self.settings)

    def has_seen_telemetry_prompt(self) -> bool:
        """Check if user has already seen the opt-in prompt."""
        if self.settings.telemetry_enabled is not None:
            return True

        # Check legacy file
        return (self.settings.output_dir / "optin").exists()

    @staticmethod
    def anonymize_ip(ip: str) -> str:
        """Anonymize IP by replacing last 2 octets with 0.0."""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0"
        return ip

    @staticmethod
    def anonymize_mac(mac: Optional[str]) -> Optional[str]:
        """Anonymize MAC by keeping only vendor prefix (first 3 octets)."""
        if not mac:
            return None
        # Handle different MAC formats (: or -)
        separator = ":" if ":" in mac else "-"
        parts = re.split(r"[:\-]", mac)
        if len(parts) == 6:
            return (
                f"{parts[0]}{separator}{parts[1]}{separator}{parts[2]}{separator}"
                f"00{separator}00{separator}00"
            )
        return mac

    def anonymize_scan_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Anonymize sensitive data in scan results."""
        # Use json for deep copy to ensure we don't modify original
        anon = json.loads(json.dumps(data))

        # Remove is_demo field - we only use this locally
        anon.pop("is_demo", None)

        # Ensure top-level device_id is correct and long enough for API
        anon["device_id"] = self.settings.device_id

        # Anonymize hosts
        if "hosts" in anon:
            for host in anon["hosts"]:
                if "ip" in host:
                    host["ip"] = self.anonymize_ip(host["ip"])
                if "mac" in host:
                    host["mac"] = self.anonymize_mac(host["mac"])
                if "hostname" in host:
                    host["hostname"] = ""  # Remove hostname entirely
                if "host" in host:  # password_scan uses "host" key
                    host["host"] = self.anonymize_ip(host["host"])

        # Anonymize results (password_scan and cve_scan)
        if "results" in anon:
            for res in anon["results"]:
                if "ip" in res:
                    res["ip"] = self.anonymize_ip(res["ip"])

                # Normalize CVE severity for API literal requirements
                if "cves" in res:
                    for cve in res["cves"]:
                        if "severity" in cve:
                            sev = str(cve["severity"]).upper()
                            if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                                cve["severity"] = "LOW"  # Fallback for 'Unknown' etc.
                            else:
                                cve["severity"] = sev

        # Anonymize target
        if "target" in anon:
            target = anon["target"]
            if "/" in target:  # CIDR notation
                parts = target.split("/")
                anon["target"] = f"{self.anonymize_ip(parts[0])}/{parts[1]}"
            elif re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
                anon["target"] = self.anonymize_ip(target)
            else:
                anon["target"] = "redacted"

        return anon

    async def submit_scan_data(
        self, scan_type: str, data: dict[str, Any]
    ) -> Optional[httpx.Response]:
        """Submit anonymized scan data to the API asynchronously."""
        if not self.is_telemetry_enabled():
            logger.debug(f"Telemetry disabled; skipping {scan_type} submission.")
            return None

        if data.get("is_demo"):
            logger.debug(f"Demo mode active; skipping {scan_type} telemetry submission.")
            return None

        try:
            session_id = self.get_session_id()
            anon_data = self.anonymize_scan_data(data)
            headers = {"X-Session-ID": session_id}

            url = f"{self.settings.api_url}/{scan_type}"

            logger.debug(f"Attempting to submit {scan_type} telemetry to {url}")

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=anon_data,
                    headers=headers,
                    timeout=self.settings.api_timeout,
                )

                # Retry once if rate limited
                if response.status_code == 429:
                    retry_after = response.json().get("retry_after", 10)
                    logger.debug(f"Rate limited. Retrying in {retry_after + 1}s...")
                    await asyncio.sleep(retry_after + 1)
                    response = await client.post(
                        url,
                        json=anon_data,
                        headers=headers,
                        timeout=self.settings.api_timeout,
                    )

            if response.status_code == 201:
                logger.debug(f"Successfully submitted {scan_type} telemetry (201 Created)")
                return response

            logger.warning(
                f"Telemetry API returned error: {response.status_code} for {scan_type} "
                f"(Method: POST, URL: {url})"
            )
            try:
                error_details = response.json()
                logger.debug(f"Response body: {json.dumps(error_details, indent=2)}")
            except Exception:
                logger.debug(f"Response body: {response.text}")

            return response
        except httpx.RequestError as e:
            logger.error(f"Network error during {scan_type} telemetry submission: {e}")
            return None
        except Exception as e:
            # Silently fail - don't interrupt user experience
            logger.error(
                f"Unexpected error during {scan_type} telemetry submission: {type(e).__name__}: {e}"
            )
            return None

    def submit_scan_data_sync(
        self, scan_type: str, data: dict[str, Any]
    ) -> Optional[httpx.Response]:
        """Submit anonymized scan data to the API synchronously."""
        if not self.is_telemetry_enabled():
            logger.debug(f"Telemetry disabled; skipping {scan_type} submission (sync).")
            return None

        if data.get("is_demo"):
            logger.debug(f"Demo mode active; skipping {scan_type} telemetry submission (sync).")
            return None

        try:
            session_id = self.get_session_id()
            anon_data = self.anonymize_scan_data(data)
            headers = {"X-Session-ID": session_id}

            url = f"{self.settings.api_url}/{scan_type}"

            logger.debug(f"Attempting to submit {scan_type} telemetry to {url} (sync)")

            with httpx.Client() as client:
                response = client.post(
                    url,
                    json=anon_data,
                    headers=headers,
                    timeout=self.settings.api_timeout,
                )

                # Retry once if rate limited
                if response.status_code == 429:
                    retry_after = response.json().get("retry_after", 10)
                    logger.debug(f"Rate limited. Retrying in {retry_after + 1}s...")
                    time.sleep(retry_after + 1)
                    response = client.post(
                        url,
                        json=anon_data,
                        headers=headers,
                        timeout=self.settings.api_timeout,
                    )

            if response.status_code == 201:
                logger.debug(f"Successfully submitted {scan_type} telemetry (sync, 201 Created)")
                return response

            logger.warning(
                f"Telemetry API returned error: {response.status_code} for {scan_type} "
                f"(sync, Method: POST, URL: {url})"
            )
            try:
                error_details = response.json()
                logger.debug(f"Response body: {json.dumps(error_details, indent=2)}")
            except Exception:
                logger.debug(f"Response body: {response.text}")

            return response
        except httpx.RequestError as e:
            logger.error(f"Network error during {scan_type} telemetry submission (sync): {e}")
            return None
        except Exception as e:
            # Silently fail - don't interrupt user experience
            logger.error(
                f"Unexpected error during {scan_type} telemetry submission (sync): "
                f"{type(e).__name__}: {e}"
            )
            return None
