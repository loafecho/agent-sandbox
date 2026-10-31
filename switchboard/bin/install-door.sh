#!/usr/bin/env bash
# Give one box its switchboard door: import/update the generated provider profile on the agent host (the
# interactive gateway's `openshell` install), then load the token from the secrets manager and attach it
# (boxes/<box>/bin/set-provider.sh).
#   switchboard/bin/install-door.sh coder
# Re-run after `python3 switchboard/gen.py` changes the profile. Never prints a token.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT="${1:?usage: install-door.sh <agent>}"
read -r BOX PROV < <(python3 -c "import yaml,sys;a=yaml.safe_load(open('$REPO/switchboard/tools.yaml'))['agents']['$AGENT'];print(a['box'],a['provider'])")
[ "$BOX" = coder ] || { echo "!! installs doors on the interactive gateway (box coder) only"; exit 2; }
F="$REPO/boxes/$BOX/openshell/profile-$PROV.yaml"
M="${AGENT_HOST:-admin@172.16.0.32}"; K="${AGENT_HOST_KEY:-$HOME/.ssh/id_agent_host}"
# Staged in a fresh 0700 directory (and mktemp below), never a fixed /tmp name another local account could
# create first and rewrite before root installs it.
D="$(ssh -i "$K" -o IdentitiesOnly=yes -o BatchMode=yes "$M" 'mktemp -d /tmp/door-XXXXXX')"
[[ "$D" == /tmp/door-* ]] || { echo "!! no staging directory on the agent host"; exit 1; }
scp -q -i "$K" -o IdentitiesOnly=yes -o BatchMode=yes "$F" "$M:$D/profile-$PROV.yaml"
ssh -i "$K" -o IdentitiesOnly=yes -o BatchMode=yes "$M" "set -e
  sudo install -o openshell -g openshell -m 640 $D/profile-$PROV.yaml /var/lib/openshell/profile-$PROV.yaml; rm -rf $D
  sudo -u openshell -H sh -c 'cd; p=$PROV
    if openshell profile list 2>/dev/null | grep -q \"^\$p \"; then cur=\$(openshell profile export \$p | sed -n \"s/^resource_version: //p\"); t=\$(mktemp); sed \"s/^resource_version: .*/resource_version: \$cur/\" profile-\$p.yaml > \$t; openshell profile update --file \$t \$p >/dev/null; rm -f \$t; echo profile \$p updated;
    else openshell profile lint --file profile-\$p.yaml >/dev/null || { echo lint FAILED; exit 1; }; openshell profile import --file profile-\$p.yaml >/dev/null; echo profile \$p imported; fi'"
"$REPO/boxes/$BOX/bin/set-provider.sh" "$PROV" --attach
