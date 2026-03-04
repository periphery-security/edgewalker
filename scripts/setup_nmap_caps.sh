#!/bin/bash

# setup_nmap_caps.sh - Grant nmap necessary capabilities to run without sudo
# This script requires sudo to apply the capabilities.

set -e

NMAP_PATH=$(which nmap)

if [ -z "$NMAP_PATH" ]; then
    echo "Error: nmap not found in PATH."
    exit 1
fi

echo "Applying capabilities to $NMAP_PATH..."
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_PATH"

echo "Success! nmap can now perform SYN scans and OS detection without sudo."
echo "Verification:"
getcap "$NMAP_PATH"
