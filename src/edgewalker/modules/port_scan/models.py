"""Pydantic models for the Port Scan module."""

# Standard Library
from typing import Annotated, Optional

# Third Party
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    PlainValidator,
    field_serializer,
)

# First Party
from edgewalker.core.models import Base, validate_mac


class UdpPort(BaseModel):
    """UDP port model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        if key == "service":
            return self.name
        if key == "product":
            return self.product_name
        if key == "version":
            return self.product_version
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(key) from e

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        if not isinstance(key, str):
            return default
        if key == "service":
            return self.name
        if key == "product":
            return self.product_name
        if key == "version":
            return self.product_version
        return getattr(self, key, default)

    port: int = Field(description="Port number", ge=0, le=65535)
    name: str = Field(description="Name of protocol for port")
    product_name: Optional[str] = Field(default=None, description="Name of product using port")
    product_version: Optional[str] = Field(
        default=None, description="Version of product using field"
    )


class TcpPort(BaseModel):
    """TCP port model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        if key == "service":
            return self.name
        if key == "product":
            return self.product_name
        if key == "version":
            return self.product_version
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(key) from e

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        if not isinstance(key, str):
            return default
        if key == "service":
            return self.name
        if key == "product":
            return self.product_name
        if key == "version":
            return self.product_version
        return getattr(self, key, default)

    port: int = Field(description="Port number", ge=0, le=65535)
    name: str = Field(description="Name of protocol for port")
    product_name: Optional[str] = Field(default=None, description="Name of product using port")
    product_version: Optional[str] = Field(
        default=None, description="Version of product using field"
    )


class Host(BaseModel):
    """Host model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __getitem__(self, key: str) -> object:
        """Allow subscriptable access."""
        if not isinstance(key, str):
            raise TypeError(f"attribute name must be string, not {type(key).__name__!r}")
        # Map old field names
        if key == "tcp_ports":
            return self.tcp
        if key == "udp_ports":
            return self.udp
        if key == "os_matches":
            return [{"name": os} for os in self.os]
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(key) from e

    def get(self, key: str, default: object = None) -> object:
        """Allow .get() access."""
        if not isinstance(key, str):
            return default
        if key == "tcp_ports":
            return self.tcp
        return self.udp if key == "udp_ports" else getattr(self, key, default)

    ip: IPvAnyAddress = Field(description="IP Address of host")
    mac: Annotated[str, PlainValidator(validate_mac)] = Field(description="MAC Address of host")
    hostname: str = Field(default="", description="Hostname of host")
    vendor: str = Field(default="Unknown", description="Vendor of host")
    state: str = Field(default="up", description="State of host")
    udp: list[UdpPort] = Field(default_factory=list, description="List of open UDP ports on host")
    tcp: list[TcpPort] = Field(default_factory=list, description="List of open TCP ports on host")
    os: list[str] = Field(default_factory=list, description="Top 3 most likely guesses at host OS")

    # Enhanced Discovery Fields
    mdns_name: Optional[str] = Field(default=None, description="Name discovered via mDNS")
    upnp_info: Optional[dict[str, str]] = Field(
        default=None, description="Information discovered via UPnP"
    )
    http_server: Optional[str] = Field(default=None, description="HTTP Server header")
    http_title: Optional[str] = Field(default=None, description="HTTP page title")

    @field_serializer("ip")
    def serialize_ip(self, ip: IPvAnyAddress, info: object) -> str:
        """Serializes an IP address to a string for display purposes.

        Args:
            ip (IPvAnyAddress): IP address to be serialized
            info (_type_): info about the context of the serializer

        Returns:
            str: IP address as a string
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

    @field_serializer("mac")
    def serialize_mac(self, mac: str, info: object) -> str:
        """Serializes a MAC address to a string for display purposes.

        Args:
            mac (str): MAC address to be serialized
            info (_type_): info about the context of the serializer

        Returns:
            str: MAC address as a string
        """
        if not info.context or info.context.get("mode") != "public":
            return mac
        arr = mac.split(":")[:3]
        arr += ["00", "00", "00"]
        return ":".join(arr)


class PortScanModel(Base):
    """Port scan model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

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

    hosts: list[Host] = Field(default_factory=list, description="List of hosts found")
    gateway_ip: Optional[str] = Field(
        default=None, description="Detected gateway IP for the subnet"
    )

    all_ports: bool = Field(default=False, description="True for full_scan")
    version_scan: bool = Field(
        default=False, description="True if we scan for software versions also"
    )

    success: bool = Field(default=True, description="True if scan was successful")
    target: str = Field(default="", description="Target of scan")
    scan_type: str = Field(default="quick", description="Type of scan (quick or full)")
    hosts_responded: int = Field(default=0, description="Number of hosts that responded")
    hosts_with_ports: int = Field(default=0, description="Number of hosts with open ports")
    error: Optional[str] = Field(default=None, description="Error message if any")
