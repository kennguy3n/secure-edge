#!/bin/sh
# Linux postinstall (.deb / .rpm).
# Enables and starts the systemd unit and applies DNS handoff.
# Idempotent: re-running on an already-installed box is harmless.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable secure-edge.service || true
    systemctl restart secure-edge.service || true
fi

mkdir -p /var/lib/secure-edge
chmod 0750 /var/lib/secure-edge

if [ -x /usr/share/secure-edge/configure-dns.sh ]; then
    /usr/share/secure-edge/configure-dns.sh apply || true
fi

exit 0
