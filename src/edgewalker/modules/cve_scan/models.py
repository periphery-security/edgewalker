"""Pydantic models for the CVE Scan module."""

# Standard Library
from typing import Optional

# Third Party
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_serializer

# First Party
from edgewalker.core.models import Base


class CveModel(BaseModel):
    """Model for storing CVE details."""

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        return getattr(self, key)

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        return getattr(self, key, default)

    id: str = Field(description="CVE ID")
    description: str = Field(description="CVE description")
    severity: str = Field(description="CVE severity")
    score: float = Field(description="CVSS base score")


class CveScanResultModel(BaseModel):
    """Model for storing CVE scan results for a single service."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        return getattr(self, key)

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        return getattr(self, key, default)

    ip: IPvAnyAddress = Field(description="Target IP address")
    port: int = Field(description="Target port number")
    service: str = Field(description="Service name")
    product: str = Field(description="Product name")
    version: str = Field(description="Product version")
    cves: list[CveModel] = Field(default_factory=list, description="List of CVEs found")
    device_correlation_id: Optional[str] = Field(
        default=None, description="Anonymous ID for correlating devices across scans"
    )

    @field_serializer("ip")
    def serialize_ip(self, ip: IPvAnyAddress, info: object) -> str:
        """Serialize IP address to a string representation based on context mode.

        Args:
            ip (IPvAnyAddress): IP address to be serialized
            info (_type_): Context information

        Returns:
            str: Serialized IP address
        """
        if not info.context or info.context.get("mode") != "public":
            return str(ip)
        if ip.version == 4:
            arr = ["0", "0"]
            arr += str(ip).split(".")[2:]
            return ".".join(arr)
        else:
            arr = ["0000", "0000", "0000", "0000"]
            arr += ip.exploded.split(":")[4:]
            return ":".join(arr)


class CveScanModel(Base):
    """Model for storing CVE scan results."""

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(key) from e

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        return getattr(self, key, default)

    results: list[CveScanResultModel] = Field(description="List of CVE scan results")

    summary: dict = Field(default_factory=dict, description="Summary of scan results")
    hosts: list = Field(
        default_factory=list, description="List of hosts (for backward compatibility)"
    )
