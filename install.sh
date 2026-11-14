#!/usr/bin/env bash
# =============================================================================
# install.sh — put netmap on the PATH
# =============================================================================
#     sudo bash ./install.sh
#
# Installs /usr/local/lib/netmap/netmap.py and /usr/local/bin/netmap.
# Idempotent, and it does not touch ~/.netmap, so your scans survive.
# =============================================================================

set -e
SRC="$(cd "$(dirname "$0")" && pwd)"

install -d /usr/local/lib/netmap
install -m 644 -T "$SRC/netmap.py" /usr/local/lib/netmap/netmap.py
install -m 755 -T "$SRC/netmap" /usr/local/bin/netmap
install -m 755 -T "$SRC/netmapupdate" /usr/local/bin/netmapupdate

# The installed launcher must point at the installed copy, not at the checkout.
cat > /usr/local/bin/netmap <<'EOF'
#!/bin/sh
exec python3 /usr/local/lib/netmap/netmap.py "$@"
EOF
chmod 755 /usr/local/bin/netmap
sed -i 's/\r$//' /usr/local/bin/netmap /usr/local/bin/netmapupdate

echo "installed /usr/local/bin/netmap"
echo "          /usr/local/bin/netmapupdate"
for t in nmap arp-scan; do
  command -v "$t" >/dev/null 2>&1 && echo "  ok      $t" \
    || echo "  missing $t  (apt install $t) - netmap falls back, just slower"
done
echo
echo "  sudo netmap          scan, save, dashboard"
echo "  sudo netmap --help   the rest"
