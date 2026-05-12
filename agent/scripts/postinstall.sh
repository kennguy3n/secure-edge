#!/bin/sh
# Post-install script for the secure-edge-agent .deb package.
# Reloads systemd, enables the unit, and starts the service.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable secure-edge.service || true
    systemctl restart secure-edge.service || true
fi

# Ensure the state directory exists for the singleton SQLite DB.
mkdir -p /var/lib/secure-edge
chmod 0750 /var/lib/secure-edge

exit 0
