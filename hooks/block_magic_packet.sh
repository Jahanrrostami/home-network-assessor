#!/bin/bash
# Log-only hook. It does not change a firewall.
# The monitor passes one MAC or one private IPv4 address.
# Edit this only for a router you administer, and keep the check below.

set -euo pipefail

TARGET="${1:-}"
if [[ ! "$TARGET" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] && [[ ! "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Refusing a target that is not a MAC or an IPv4 address." >&2
  exit 2
fi

echo "[hook] Magic-packet block requested for ${TARGET}"
echo "[hook] No firewall change was made. Adapt this script to your own router before it can do anything else."
exit 0
