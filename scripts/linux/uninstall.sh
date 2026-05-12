#!/usr/bin/env bash
# Stand-alone Linux uninstaller (for users who installed manually
# rather than via the .deb / .rpm packages). Safe to re-run.
#
# Run as root: `sudo ./uninstall.sh`.

set -u

if [ -x /usr/share/secure-edge/configure-dns.sh ]; then
    /usr/share/secure-edge/configure-dns.sh restore || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop secure-edge.service 2>/dev/null || true
    systemctl disable secure-edge.service 2>/dev/null || true
fi

rm -f /usr/bin/secure-edge-agent
rm -f /lib/systemd/system/secure-edge.service
rm -rf /etc/secure-edge /var/lib/secure-edge /usr/share/secure-edge

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

echo "Secure Edge uninstalled."
exit 0
