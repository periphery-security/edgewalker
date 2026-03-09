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
from pydantic import Field, ValidationInfo, field_validator
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


def get_data_dir() -> Path:
    """Return the user-facing data directory for scan results.

    Defaults to ~/.edgewalker so results are easy to find and separate
    from the application config in Library/Application Support (macOS)
    or ~/.config (Linux).  Override with EW_DATA_DIR.
    """
    return Path(os.environ.get("EW_DATA_DIR", Path.home() / ".edgewalker"))


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
        validate_assignment=True,
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

    @field_validator("api_url", "nvd_api_url", "mac_api_url")
    @classmethod
    def validate_urls(cls, v: str, info: ValidationInfo) -> str:
        """Ensure URLs use https and warn if they point to unexpected domains."""
        # Skip strict https enforcement during tests if using http
        if os.environ.get("PYTEST_CURRENT_TEST") and v.startswith("http://"):
            return v

        if not v.startswith("https://"):
            # Allow http for localhost/127.0.0.1
            if not any(x in v for x in ("localhost", "127.0.0.1")):
                raise ValueError(f"{info.field_name} must use https for security")

        # Domain warnings
        if info.field_name == "api_url":
            if ".periphery.security" not in v and not any(
                x in v for x in ("localhost", "127.0.0.1")
            ):
                logger.warning(f"Non-standard EdgeWalker API URL detected: {v}")
        elif info.field_name == "nvd_api_url":
            if "services.nvd.nist.gov" not in v and not any(
                x in v for x in ("localhost", "127.0.0.1")
            ):
                logger.warning(
                    f"Non-standard NVD API URL detected: {v}. "
                    "Ensure you trust this endpoint as it receives your API key!"
                )
        elif info.field_name == "mac_api_url":
            if "api.maclookup.app" not in v and not any(x in v for x in ("localhost", "127.0.0.1")):
                logger.warning(
                    f"Non-standard MAC Lookup API URL detected: {v}. "
                    "Ensure you trust this endpoint as it receives your API key!"
                )

        return v

    @field_validator("output_dir", mode="after")
    @classmethod
    def handle_demo_mode(cls, v: Path) -> Path:
        """Ensure output_dir points to demo_scans when in demo mode."""
        if os.environ.get("EW_DEMO_MODE") == "1":
            return get_data_dir() / "demo_scans"
        return v

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
    mac_api_url: str = Field(
        default="https://api.maclookup.app/v2/macs",
        description="MACLookup API base URL",
    )
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
        default_factory=lambda: (
            get_data_dir() / "demo_scans"
            if os.environ.get("EW_DEMO_MODE") == "1"
            else get_data_dir() / "scans"
        ),
        description="Output directory for scan results (~/.edgewalker/scans by default)",
    )
    creds_file: Path = Field(
        default=Path(__file__).parent.parent / "data" / "creds.csv",
        description="Path to the bundled credential database",
    )

    telemetry_enabled: Optional[bool] = Field(
        default=None,
        description="User opt-in status for anonymous data sharing",
    )

    silent_mode: bool = Field(
        default=False,
        description="Run in non-interactive mode (bypass prompts)",
    )

    unprivileged: bool = Field(
        default=False,
        description="Run without sudo using TCP connect scans (macOS/no-root).",
    )

    suppress_warnings: bool = Field(
        default=False,
        description="Suppress configuration and security warnings in the console",
    )

    accept_telemetry: bool = Field(
        default=False,
        description="Explicitly opt-in to telemetry (used in silent mode)",
        exclude=True,
    )

    decline_telemetry: bool = Field(
        default=False,
        description="Explicitly opt-out of telemetry (used in silent mode)",
        exclude=True,
    )

    theme: str = Field(
        default="periphery",
        description="Active theme slug",
    )

    device_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this installation (Read-only)",
    )

    def get_security_warnings(self) -> list[str]:
        """Identify non-standard or insecure security-sensitive settings.

        Returns:
            A list of warning messages.
        """
        # Skip security warnings during tests or if suppressed
        if os.environ.get("PYTEST_CURRENT_TEST") or self.suppress_warnings:
            return []

        warnings = []

        # Check api_url
        if ".periphery.security" not in self.api_url and not any(
            x in self.api_url for x in ("localhost", "127.0.0.1")
        ):
            warnings.append(f"Non-standard EdgeWalker API URL: {self.api_url}")

        # Check nvd_api_url
        if "services.nvd.nist.gov" not in self.nvd_api_url and not any(
            x in self.nvd_api_url for x in ("localhost", "127.0.0.1")
        ):
            warnings.append(
                f"Non-standard NVD API URL: {self.nvd_api_url}. "
                "Ensure you trust this endpoint as it receives your API key!"
            )

        # Check mac_api_url
        if "api.maclookup.app" not in self.mac_api_url and not any(
            x in self.mac_api_url for x in ("localhost", "127.0.0.1")
        ):
            warnings.append(
                f"Non-standard MAC Lookup API URL: {self.mac_api_url}. "
                "Ensure you trust this endpoint as it receives your API key!"
            )

        # Check for non-https (should be caught by validator but extra safety)
        for field in ("api_url", "nvd_api_url", "mac_api_url"):
            val = getattr(self, field)
            if not val.startswith("https://") and not any(
                x in val for x in ("localhost", "127.0.0.1")
            ):
                warnings.append(f"Insecure (non-HTTPS) {field.replace('_', ' ').upper()}: {val}")

        return warnings

    def get_field_info(self, name: str) -> dict[str, object]:
        """Get detailed information about a configuration field.

        Args:
            name: The name of the field.

        Returns:
            A dictionary containing:
            - value: Current value
            - default: Default value
            - is_overridden: True if overridden by env/dotenv
            - override_source: Source of override (if any)
            - is_modified: True if value differs from default
            - security_warning: Security warning message (if any)
        """
        if name not in self.model_fields:
            raise AttributeError(f"Setting '{name}' does not exist.")

        field = self.model_fields[name]
        value = getattr(self, name)
        default = field.default

        overrides = get_active_overrides()
        env_key = f"EW_{name.upper()}"
        alias = field.alias if field.alias else None

        override_source = overrides.get(env_key) or (overrides.get(alias) if alias else None)
        is_overridden = override_source is not None

        # Check for security warnings
        security_warning = None
        field_label = name.replace("_", " ").upper()
        for warning in self.get_security_warnings():
            if field_label in warning.upper():
                security_warning = warning
                break

        return {
            "value": value,
            "default": default,
            "is_overridden": is_overridden,
            "override_source": override_source,
            "is_modified": value != default,
            "security_warning": security_warning,
        }


settings = Settings()


def get_active_overrides() -> dict[str, str]:
    """Identify settings currently overridden by environment variables or .env.

    Returns:
        A dictionary mapping the environment variable key to its source
        ('environment variable' or '.env file').
    """
    # Skip overrides during tests to ensure consistent behavior
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("EW_ALLOW_OVERRIDES_IN_TESTS"):
        return {}

    overrides = {}

    # Check .env file first (lower precedence than env vars)
    env_file = Path(".env")
    if env_file.exists():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key = line.split("=")[0].strip()
                        if key.startswith("EW_"):
                            overrides[key] = ".env file"
        except (OSError, UnicodeDecodeError):
            pass  # nosec: B110 - best effort loading of .env file

    # Check environment variables (higher precedence)
    for key in os.environ:
        if key.startswith("EW_") and key != "EW_ALLOW_OVERRIDES_IN_TESTS":
            overrides[key] = "environment variable"

    return overrides


def init_config() -> None:
    """Initialize the config file with default settings if it does not exist."""
    get_config_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(get_config_dir(), 0o700)
    settings.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(settings.output_dir, 0o700)
    config_file = settings.config_file

    # Check for overrides and notify user
    overrides = get_active_overrides()
    if overrides:
        sources = ", ".join(sorted(set(overrides.values())))
        logger.warning(
            f"Configuration overrides detected from {sources}. "
            "These settings will take precedence over config.yaml."
        )
        for key, source in overrides.items():
            logger.debug(f"Override active: {key} from {source}")

    # Check for security-sensitive non-standard settings
    for warning in settings.get_security_warnings():
        logger.warning(warning)

    # Check for root ownership of config file (common if run with sudo first)
    if config_file.exists() and os.getuid() != 0:
        try:
            if config_file.stat().st_uid == 0:
                logger.warning(
                    f"Config file '{config_file}' is owned by root. "
                    "Settings changes will not be saved. "
                    f"Run 'sudo chown {os.getlogin()} \"{config_file}\"' to fix."
                )
        except (OSError, AttributeError):
            pass

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
    get_config_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(get_config_dir(), 0o700)
    config_file = settings_obj.config_file

    data = settings_obj.model_dump(mode="json")

    # Paths need to be stringified for YAML
    data["cache_dir"] = str(settings_obj.cache_dir.absolute())
    data["output_dir"] = str(settings_obj.output_dir.absolute())
    data["theme"] = settings_obj.theme

    # Open with restricted permissions (0o600: read/write for owner only)
    try:
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.dump(data, f, sort_keys=False)
    except PermissionError:
        logger.warning(
            f"Permission denied when saving config to '{config_file}'. "
            "If you previously ran with sudo, you may need to fix file ownership: "
            f'sudo chown {os.getlogin()} "{config_file}"'
        )
    except Exception as e:
        logger.error(f"Failed to save settings to {config_file}: {e}")


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
