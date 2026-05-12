#!/usr/bin/env bash
# Reverse the installation done by build-pkg.sh / postinstall.sh.
#
# Steps (best-effort: continues on any single failure):
#   1. Restore DNS to the previous setting.
#   2. Unload the LaunchDaemon.
#   3. Remove the binary, plist, rules, and config.
#
# Run as root: `sudo ./uninstall.sh`.

set -u

PLIST="/Library/LaunchDaemons/com.secureedge.agent.plist"
BINARY="/usr/local/bin/secure-edge-agent"
CONFIG_DIR="/etc/secure-edge"
LIB_DIR="/var/lib/secure-edge"

# Restore DNS first so the box stays online even if the rest fails.
if [ -x "/usr/local/share/secure-edge/configure-dns.sh" ]; then
  /usr/local/share/secure-edge/configure-dns.sh restore || true
elif [ -x "$(dirname "$0")/configure-dns.sh" ]; then
  "$(dirname "$0")/configure-dns.sh" restore || true
fi

launchctl bootout system "${PLIST}" 2>/dev/null || true

rm -f "${PLIST}" "${BINARY}"
rm -rf "${CONFIG_DIR}" "${LIB_DIR}"

echo "Secure Edge uninstalled."
exit 0
