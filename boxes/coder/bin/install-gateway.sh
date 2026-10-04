#!/usr/bin/env bash
# B1: OpenShell gateway on the agent host (VM 150 in the examples). Run from the admin workstation. Dry run unless
# --yes-write. Copies the host half (gateways/interactive/gateway-setup.sh + config) over the bootstrap key and runs it as root.
# Rollback: bin/install-gateway.sh --remove --yes-write  (stops the gateway, removes the package and
# the openshell user; coder's sessions are not involved).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${AGENT_HOST:-admin@172.16.0.32}"
KEY="${AGENT_HOST_KEY:-$HOME/.ssh/id_agent_host}"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -i "$KEY" "$HOST")
MODE=""; REMOVE=0
for a in "$@"; do case "$a" in --yes-write) MODE=--yes-write;; --remove) REMOVE=1;; *) echo "unknown arg $a"; exit 2;; esac; done
if ((REMOVE)); then
  if [[ -z "$MODE" ]]; then echo "WOULD stop the gateway, apt-get remove openshell, userdel -r openshell on $HOST"; exit 0; fi
  "${SSH[@]}" 'U=$(id -u openshell) && sudo -u openshell -H env XDG_RUNTIME_DIR=/run/user/$U systemctl --user disable --now openshell-gateway; sudo loginctl disable-linger openshell; sudo apt-get remove -y -qq openshell; sudo userdel -r openshell; id openshell 2>&1'
  exit 0
fi
"${SSH[@]}" 'rm -rf /tmp/coder-box-setup && mkdir -m 700 /tmp/coder-box-setup'
GW="$HERE/../../gateways/interactive"
files=("$GW/gateway-setup.sh" "$GW/gateway.toml.tmpl")
[[ -f "$GW/gateway.env" ]] && files+=("$GW/gateway.env")   # optional: extra environment for the gateway service
scp -q -o BatchMode=yes -i "$KEY" "${files[@]}" "$HOST:/tmp/coder-box-setup/"
"${SSH[@]}" "sudo bash /tmp/coder-box-setup/gateway-setup.sh $MODE; rc=\$?; rm -rf /tmp/coder-box-setup; exit \$rc"
