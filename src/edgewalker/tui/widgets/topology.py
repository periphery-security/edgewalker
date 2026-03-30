"""EdgeWalker TUI Topology Widget — Interactive network map."""

from __future__ import annotations

# Standard Library
from typing import Any

# Third Party
from rich.text import Text
from textual.widgets import Tree

# First Party
from edgewalker import theme
from edgewalker.core.risk import RiskEngine


class TopologyWidget(Tree):
    """An interactive tree widget that renders the network topology map."""

    def __init__(self, scan_results: dict[str, Any], **kwargs: object) -> None:
        """Initialize the topology widget.

        Args:
            scan_results: The scan results dictionary.
            **kwargs: Additional widget arguments.
        """
        # Use "Internet" as the root label
        root_label = Text(f" {theme.ICON_SCAN} Internet (Cloud)", style=theme.ACCENT)
        super().__init__(root_label, **kwargs)
        self.scan_results = scan_results
        self.root.expand()
        self._populate_tree()

    def _populate_tree(self) -> None:
        """Populate the tree with gateway and devices."""
        if not self.scan_results:
            return

        hosts = self.scan_results.get("hosts", [])
        gateway_ip = self.scan_results.get("gateway_ip")

        # Identify gateway and other devices
        gateway = None
        other_devices = []

        for host in hosts:
            if str(host.get("ip")) == str(gateway_ip):
                gateway = host
            else:
                other_devices.append(host)

        # 1. Add Gateway
        gw_risk = gateway.get("risk", {}).get("score", 0) if gateway else 0
        _, gw_color = RiskEngine.get_risk_level(gw_risk)
        gw_name = (
            gateway.get("hostname") or gateway.get("ip")
            if gateway
            else gateway_ip or "Unknown Gateway"
        )
        gw_vendor = (
            f" ({gateway.get('vendor')})" if gateway and gateway.get("vendor") != "Unknown" else ""
        )

        gw_label = Text(f"{theme.ICON_WARN} Gateway: {gw_name}{gw_vendor}", style=gw_color)
        gw_node = self.root.add(gw_label, data=gateway, expand=True)

        # 2. Add EdgeWalker Scanner (This machine) under Gateway
        scanner_label = Text(
            f"{theme.ICON_CHECK} EdgeWalker Scanner (This Machine)", style=theme.PRIMARY
        )
        gw_node.add_leaf(scanner_label, data={"type": "scanner"})

        # 3. Add Other Devices under Gateway
        if other_devices:
            for device in other_devices:
                dev_risk = device.get("risk", {}).get("score", 0)
                _, dev_color = RiskEngine.get_risk_level(dev_risk)

                dev_name = device.get("hostname") or device.get("ip")
                dev_vendor = (
                    f" ({device.get('vendor')})" if device.get("vendor") != "Unknown" else ""
                )

                dev_label = Text(f"{theme.ICON_PLUS} {dev_name}{dev_vendor}", style=dev_color)
                gw_node.add_leaf(dev_label, data=device)
        else:
            gw_node.add_leaf(Text("(No other devices discovered)", style=theme.MUTED))
