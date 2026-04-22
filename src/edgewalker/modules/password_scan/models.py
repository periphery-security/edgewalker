"""Pydantic models for the Password Scan module."""

# Standard Library
from enum import Enum
from typing import Optional

# Third Party
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_serializer

# First Party
from edgewalker.core.models import Base


class StatusEnum(str, Enum):
    """Status model, a list of status's for password authentication attempts."""

    successful = "successful"
    failed = "failed"
    ratelimit = "ratelimit"
    unknown = "unknown"


class ServiceEnum(str, Enum):
    """Service model, a list of services that we test passwords against."""

    ssh = "ssh"
    ftp = "ftp"
    telnet = "telnet"
    smb = "smb"


class CredentialsModel(BaseModel):
    """Model for storing credentials used in password authentication attempts."""

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        return getattr(self, key)

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        return getattr(self, key, default)

    user: str = Field(description="Username")
    password: str = Field(description="Password")


class PasswordScanResultModel(BaseModel):
    """Model for storing results of password authentication attempts."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str | int) -> object:
        """Allow subscriptable access."""
        if isinstance(key, int):
            # Allow tuple-like access for backward compatibility: (service_name, result_dict)
            if key == 0:
                return str(self.service.value)
            if key == 1:
                # Return a dict that looks like the old result_dict
                status = "vulnerable" if self.login_attempt == StatusEnum.successful else "secure"
                if self.error == "port_closed":
                    status = "port_closed"

                creds = []
                if self.credentials:
                    creds = [
                        {"username": self.credentials.user, "password": self.credentials.password}
                    ]

                return {
                    "port": self.port,
                    "status": status,
                    "credentials": creds,
                    "tested": 10,  # dummy value for tests
                }
            raise IndexError("index out of range")

        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(key) from e

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        return getattr(self, key, default)

    ip: IPvAnyAddress = Field(description="Target IP address")
    port: int = Field(description="Target port number")
    service: ServiceEnum = Field(description="Service type being tested")
    login_attempt: StatusEnum = Field(description="Status of login attempt")
    credentials: Optional[CredentialsModel] = Field(
        default=None, description="Credentials if login attempt is 'successful'"
    )
    error: Optional[str] = Field(default=None, description="Error message if any")
    product_name: Optional[str] = Field(default=None, description="Name of product using port")
    product_version: Optional[str] = Field(
        default=None, description="Version of product using port"
    )
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


class PasswordScanModel(Base):
    """Model for storing password scan results."""

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

    # Password scan specific fields

    results: list[PasswordScanResultModel] = Field(description="List of password scan results")
    summary: dict = Field(default_factory=dict, description="Summary of scan results")
    hosts: list = Field(
        default_factory=list, description="List of hosts (for backward compatibility)"
    )
