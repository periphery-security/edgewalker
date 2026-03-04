"""Core Pydantic models for EdgeWalker."""

# Standard Library
import re
from datetime import datetime, timezone
from typing import Annotated, Optional

# Third Party
import semver
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_serializer,
)


def validate_mac(mac: str) -> str:
    """Validate MAC address format.

    Args:
        mac (str): MAC address to validate.

    Returns:
        str: Validated MAC address.

    Raises:
        ValueError: If MAC address format is invalid.
    """
    if not mac:
        return ""
    # Support common formats: 00:11:22:33:44:55, 00-11-22-33-44-55, 0011.2233.4455, 001122334455
    clean_mac = re.sub(r"[.:\-]", "", mac).upper()
    if len(clean_mac) != 12 or not all(c in "0123456789ABCDEF" for c in clean_mac):
        raise ValueError(f"Invalid MAC address format: {mac}")

    # Return in standard colon-separated format
    return ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))


def valid_version(version: str | semver.VersionInfo) -> semver.VersionInfo:
    """Validate a version string and return a SemVer object if valid.

    Args:
        version (str): The version string to validate.

    Returns:
        semver.VersionInfo: A SemVer object representing the validated version.
    """
    if isinstance(version, semver.VersionInfo):
        return version
    return semver.VersionInfo.parse(version, optional_minor_and_patch=True)


class Base(BaseModel):
    """Base model for all modules in the application."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access for backward compatibility with dict-based code."""
        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access for backward compatibility."""
        if not isinstance(key, str):
            return default
        return getattr(self, key, default)

    def __eq__(self, other: object) -> bool:
        """Allow comparison with dictionaries for backward compatibility with tests."""
        if isinstance(other, dict):
            return self.model_dump(mode="json") == other
        return super().__eq__(other)

    id: str = Field(
        default_factory=lambda: "test-id", description="Unique identifier for the report."
    )
    device_id: str = Field(
        default="test-device", description="Unique identifier for the module. (hash of MAC address)"
    )
    version: Annotated[
        semver.VersionInfo,
        Field(default="0.1.0", description="Version number of the CLI."),
        BeforeValidator(valid_version),
    ]
    module: str = Field(default="unspecified", description="Name of the module that ran.")
    module_version: Annotated[
        semver.VersionInfo,
        Field(default="0.1.0", description="Version number of the module."),
        BeforeValidator(valid_version),
    ]
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the module was run.",
    )

    @field_serializer("version")
    def serialize_version(self, version: semver.VersionInfo, _info: object) -> str:
        """Serialize a semver.VersionInfo object to a string.

        Args:
            version (semver.VersionInfo): VersionInfo object to be serialized.
            _info (_type_): Unused field for serialization.

        Returns:
            str: Serialized version number as a string.
        """
        return str(version)

    @field_serializer("module_version")
    def serialize_module_version(self, module_version: semver.VersionInfo, _info: object) -> str:
        """Serialize a semver.VersionInfo object to a string.

        Args:
            module_version (semver.VersionInfo): VersionInfo object to be serialized.
            _info (_type_): Unused field for serialization.

        Returns:
            str: Serialized module version as a string.
        """
        return str(module_version)


class MacSearchResult(BaseModel):
    """Pydantic model for the output of the search_mac function."""

    mac_address: str = Field(description="The original MAC address provided.")
    normalized_mac: str = Field(
        description="The normalized MAC address (uppercase, no separators)."
    )
    found: bool = Field(
        description="True if the MAC address was found in a database, False otherwise."
    )
    database: Optional[str] = Field(
        None,
        description="The database where the MAC address was found (oui, oui36, or mam), if found.",
    )
    organization: Optional[str] = Field(
        None, description="The organization associated with the MAC address, if found."
    )
    address: Optional[str] = Field(None, description="The address of the organization, if found.")
