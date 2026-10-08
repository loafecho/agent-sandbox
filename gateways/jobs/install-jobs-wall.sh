#!/usr/bin/env bash
# Render the uid-keyed egress wall (jobs-wall.nft.in) and, with --yes-write, install it on this host as root.
#   install-jobs-wall.sh --render       print the rendered ruleset (no root needed)
#   install-jobs-wall.sh                dry run: render, syntax-check with `nft -c`, show what would change
#   install-jobs-wall.sh --yes-write    render, check, install to /etc/nftables.d/jobs-wall.nft, (re)start jobs-wall.service
# Site values come from the environment; the defaults are this repo's example addresses.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HA="${JOBS_WALL_HA:-198.51.100.19}"                 # Home Assistant
SWITCHBOARD="${JOBS_WALL_SWITCHBOARD:-172.16.0.33}" # the switchboard VM
LAN_DNS="${JOBS_WALL_DNS:-172.16.0.53, 172.16.0.1}"
# Ranges the jobs user may never reach beyond the accepts above them: RFC 1918, RFC 6598 (CGNAT, which
# includes the tailnet), link-local, this-network and multicast.
PRIVATE4="$(printf '%d.0.0.0/8, 172.16.0.0/12, %d.%d.0.0/16, %d.%d.0.0/10, 169.254.0.0/16, 0.0.0.0/8, 224.0.0.0/4' 10 192 168 100 64)"

render() {
  sed -e "s|@HA@|$HA|" -e "s|@SWITCHBOARD@|$SWITCHBOARD|" -e "s|@LAN_DNS@|$LAN_DNS|" -e "s|@PRIVATE4@|$PRIVATE4|" \
    "$HERE/jobs-wall.nft.in"
}

case "${1:-}" in
  --render) render; exit 0;;
  ""|--yes-write) ;;
  *) echo "usage: $0 [--render|--yes-write]"; exit 2;;
esac
[[ $EUID -eq 0 ]] || { echo "run as root (or use --render)"; exit 2; }
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
render > "$tmp"
nft -c -f "$tmp" || { echo "FAIL: nft rejected the rendered ruleset"; exit 1; }
echo "OK   rendered ruleset passes nft -c"
if [[ "${1:-}" != "--yes-write" ]]; then
  diff -u /etc/nftables.d/jobs-wall.nft "$tmp" 2>/dev/null || true
  echo "dry run: nothing installed (--yes-write to install)"; exit 0
fi
install -d -m 755 /etc/nftables.d
install -m 644 "$tmp" /etc/nftables.d/jobs-wall.nft
install -m 644 "$HERE/jobs-wall.service" /etc/systemd/system/jobs-wall.service
systemctl daemon-reload
systemctl enable jobs-wall.service >/dev/null 2>&1
systemctl restart jobs-wall.service
nft list table inet jobs_wall | head -5
echo "installed /etc/nftables.d/jobs-wall.nft"
