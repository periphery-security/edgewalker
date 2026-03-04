"""EdgeWalker Configuration.

Centralizes all tuneable constants. Override any value via environment
variables prefixed with ``EW_`` (see inline comments for variable names).
"""

from __future__ import annotations

# Standard Library
import os
import uuid
from pathlib import Path
from typing import Optional, Union, get_args, get_origin

# Third Party
import yaml
from loguru import logger
from platformdirs import user_cache_dir, user_config_dir
from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


# ============================================================================
# CONSTANTS & PATHS
# ============================================================================
def get_config_dir() -> Path:
    """Return the configuration directory, allowing override via environment variable."""
    return Path(os.environ.get("EW_CONFIG_DIR", user_config_dir("edgewalker")))


def get_cache_dir() -> Path:
    """Return the cache directory, allowing override via environment variable."""
    return Path(os.environ.get("EW_CACHE_DIR", user_cache_dir("edgewalker")))


# Legacy constants for backward compatibility (evaluated at load time)
# Note: Tests should use EW_CONFIG_DIR/EW_CACHE_DIR env vars BEFORE importing this module
# or we need to ensure they are used dynamically.
CONFIG_DIR = get_config_dir()
CACHE_DIR = get_cache_dir()


class Settings(BaseSettings):
    """EdgeWalker Configuration Settings."""

    @property
    def config_file(self) -> Path:
        """Return the path to the configuration file."""
        return get_config_dir() / "config.yaml"

    model_config = SettingsConfigDict(
        env_prefix="EW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Customise settings sources to include YAML file."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=get_config_dir() / "config.yaml"),
            file_secret_settings,
        )

    # ============================================================================
    # API
    # ============================================================================
    api_url: str = Field(
        default="https://api.periphery.security/edgewalker/v1",
        description="Base URL for the EdgeWalker data-collection API",
    )
    api_timeout: int = Field(
        default=10,
        description="Timeout (seconds) for outbound API requests",
    )

    # ============================================================================
    # SCAN TIMEOUTS
    # ============================================================================
    nmap_timeout: int = Field(
        default=900,
        description="Max seconds an nmap subprocess may run before being killed (15 minutes)",
    )
    nmap_full_timeout: int = Field(
        default=7200,
        description="Timeout for full (all-port) scans (2 hours)",
    )
    ping_sweep_timeout: int = Field(
        default=300,
        description="Timeout for the ping-sweep phase (5 minutes)",
    )
    conn_timeout: int = Field(
        default=5,
        description="TCP connection timeout for credential tests",
    )
    nvd_rate_limit_delay: int = Field(
        default=6,
        description="Seconds between NVD API requests (rate-limit guard)",
        alias="EW_NVD_RATE_DELAY",
    )
    cred_workers: int = Field(
        default=8,
        description="Max concurrent threads for credential testing",
    )
    scan_workers: int = Field(
        default=4,
        description="Max parallel nmap subprocesses for host batches",
    )

    # ============================================================================
    # NVD
    # ============================================================================
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD CVE search endpoint",
    )
    nvd_api_key: Optional[str] = Field(
        default=None,
        description="NVD API key (increases rate limit)",
    )

    # ============================================================================
    # MAC LOOKUP
    # ============================================================================
    mac_api_key: Optional[str] = Field(
        default=None,
        description="MACLookup API key (increases rate limit from 2 to 50 req/s)",
    )

    # ============================================================================
    # PORT LISTS
    # ============================================================================
    iot_ports: list[int] = Field(
        default=[
            21,
            22,
            23,
            2323,
            5900,  # Remote access
            80,
            81,
            443,
            8080,
            8081,
            8443,  # Web interfaces
            554,
            37777,
            34567,  # Cameras & DVR
            1883,
            8883,
            502,  # IoT protocols
            53,
            161,
            1900,
            5000,
            5353,  # Discovery
            445,
            9100,
            7547,  # Network services
            8123,
            32400,  # Smart home & media
            6667,  # Suspicious
        ],
        description="Common IoT ports for quick scan",
    )

    # ============================================================================
    # RISK SCORING
    # ============================================================================
    category_weights: dict[str, float] = Field(
        default={
            "exposure": 0.25,
            "credentials": 0.40,
            "vulnerabilities": 0.35,
        },
        description="Category weights (must sum to 1.0)",
    )

    port_severity: dict[int, int] = Field(
        default={
            23: 80,  # Telnet
            5900: 70,  # VNC
            21: 60,  # FTP
            22: 30,  # SSH
        },
        description="Port severity scores (0-100)",
    )
    port_severity_default: int = Field(default=10)
    port_extra_penalty: int = Field(default=3)

    cred_severity: dict[str, int] = Field(
        default={
            "telnet": 100,
            "ftp": 90,
            "smb": 85,
            "ssh": 80,
        },
        description="Credential severity scores (0-100)",
    )
    cred_severity_default: int = Field(default=80)
    cred_extra_penalty: int = Field(default=5)

    cve_severity: dict[str, int] = Field(
        default={
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
        },
        description="CVE severity scores (0-100)",
    )
    cve_severity_default: int = Field(default=25)
    cve_extra_penalty: int = Field(default=5)

    # ============================================================================
    # PATHS
    # ============================================================================
    cache_dir: Path = Field(
        default_factory=get_cache_dir,
        description="Cache directory",
    )
    output_dir: Path = Field(
        default_factory=lambda: get_config_dir() / "scans",
        description="Output directory",
    )
    creds_file: Path = Field(
        default=Path(__file__).parent.parent / "data" / "creds.csv",
        description="Path to the bundled credential database",
    )

    telemetry_enabled: Optional[bool] = Field(
        default=None,
        description="User opt-in status for anonymous data sharing",
    )

    theme: str = Field(
        default="periphery",
        description="Active theme slug",
    )

    device_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this installation (Read-only)",
    )


settings = Settings()


def init_config() -> None:
    """Initialize the config file with default settings if it does not exist."""
    get_config_dir().mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    config_file = settings.config_file

    if not config_file.exists():
        save_settings(settings)
    else:
        # Ensure new required fields (like device_id) are persisted to existing files
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            if "device_id" not in data:
                save_settings(settings)
        except Exception as e:
            logger.debug(f"Failed to check/update existing config: {e}")


def save_settings(settings_obj: Settings) -> None:
    """Save settings to the YAML configuration file."""
    get_config_dir().mkdir(parents=True, exist_ok=True)
    config_file = settings_obj.config_file

    data = settings_obj.model_dump(mode="json")

    # Paths need to be stringified for YAML
    data["cache_dir"] = str(settings_obj.cache_dir.absolute())
    data["output_dir"] = str(settings_obj.output_dir.absolute())
    data["theme"] = settings_obj.theme

    with open(config_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False)


def update_setting(key: str, value: object) -> None:
    """Update a specific setting by key and save to disk."""
    if key == "device_id":
        raise AttributeError("The 'device_id' setting is read-only and cannot be changed.")

    if not hasattr(settings, key):
        raise AttributeError(f"Setting '{key}' does not exist.")

    # Get the field type for validation/conversion
    field = settings.__class__.model_fields.get(key)
    if field:
        # Basic type conversion for common types
        # Handle Optional types by checking the inner type
        origin = get_origin(field.annotation)
        args = get_args(field.annotation)

        target_type = field.annotation
        if origin is Union and type(None) in args:
            target_type = next(t for t in args if t is not type(None))

        if target_type is int:
            value = int(value) if value is not None else None
        elif target_type is bool:
            if isinstance(value, str):
                value = value.lower() in ("true", "1", "yes", "on")
        elif target_type is float:
            value = float(value) if value is not None else None
        elif target_type is Path:
            value = Path(value) if value is not None else None

    setattr(settings, key, value)
    save_settings(settings)
