#!/bin/sh
# Pre-remove script for the secure-edge-agent .deb package.
# Stops and disables the systemd unit before files are removed.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop secure-edge.service || true
    systemctl disable secure-edge.service || true
fi

exit 0
