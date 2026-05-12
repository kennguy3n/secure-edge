#!/bin/sh
# Linux preremove (.deb / .rpm).
# Stops and disables the systemd unit, restores DNS.

set -e

if [ -x /usr/share/secure-edge/configure-dns.sh ]; then
    /usr/share/secure-edge/configure-dns.sh restore || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop secure-edge.service || true
    systemctl disable secure-edge.service || true
fi

exit 0
