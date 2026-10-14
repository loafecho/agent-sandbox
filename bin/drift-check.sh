#!/usr/bin/env bash
# Read-only: does every OpenShell box on the agent host (and the switchboard) match this repo? Exit 0 only if every check passes.
#   bin/drift-check.sh --all              every box
#   bin/drift-check.sh coder|homebot|switchboard
# coder is a long-lived box: its own check (boxes/coder/bin/drift-check.sh) compares live rules, providers,
# profiles, Infisical names and pending rules. The job boxes are created per run and deleted, so there is
# no live box to read: the check compares the files the jobs gateway boots them from (sha256) and the
# gateway's provider list against gateways/jobs/providers.tsv. Never prints a secret value.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${AGENT_HOST:-admin@172.16.0.32}"
KEY="${AGENT_HOST_KEY:-$HOME/.ssh/id_agent_host}"
SSH=(ssh -n -o BatchMode=yes -o ConnectTimeout=10 -i "$KEY" "$HOST")
JOBS=(homebot)
FAILS=0
ok()  { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS+1)); }
jobs_sh() { "${SSH[@]}" "sudo -u openshell-jobs -H sh -c 'cd && $1'"; }

check_job() {
  local b="$1" f live repo
  for f in "$ROOT/boxes/$b/openshell/"policy.yaml "$ROOT/boxes/$b/openshell/"profile-*.yaml; do
    repo=$(sha256sum "$f" | cut -c1-64)
    live=$(jobs_sh "sha256sum /var/lib/openshell-jobs/$b/$(basename "$f")" 2>/dev/null | cut -c1-64)
    [ "$repo" = "$live" ] && ok "$b: $(basename "$f") matches" || bad "$b: $(basename "$f") differs from /var/lib/openshell-jobs/$b/ (or missing)"
  done
  local extra; extra=$(jobs_sh "ls /var/lib/openshell-jobs/$b/" 2>/dev/null | grep -E '^(policy|profile-).*\.yaml$' | while read -r n; do [ -f "$ROOT/boxes/$b/openshell/$n" ] || echo "$n"; done)
  [ -z "$extra" ] && ok "$b: no unrecorded files on the gateway" || bad "$b: on the gateway but not in the repo: $extra"
}

check_job_providers() {
  local live want
  live=$(jobs_sh "openshell provider list" 2>/dev/null | awk 'NR>1 {print $1"\t"$2}' | sort)
  want=$(grep -v '^#' "$ROOT/gateways/jobs/providers.tsv" | awk -F'\t' 'NF>=2 {print $1"\t"$2}' | sort)
  [ -n "$live" ] || { bad "jobs gateway: provider list empty or unreachable"; return; }
  [ "$live" = "$want" ] && ok "jobs gateway: providers == providers.tsv" || { bad "jobs gateway: providers differ"; diff <(echo "$want") <(echo "$live") | sed 's/^/      /'; }
}

# The switchboard (VM 160) has no SSH; read it through the Proxmox host's guest agent.
check_switchboard() {
  local PVE_HOST="${PVE_HOST:-root@pve1}" vmid=160 out
  gx() { ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$PVE_HOST" "qm guest exec $vmid -- $1" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("out-data",""),end="")'; }
  out=$(gx "systemctl is-active switchboard"); [ "$out" = "active" ] || [ "$out" = $'active\n' ] && ok "switchboard: service active" || bad "switchboard: service not active ($out)"
  local want live; want=$(cut -c1-64 "$ROOT/switchboard/deploy/EXPECTED_SHA256" 2>/dev/null); live=$(gx "sha256sum /usr/local/bin/switchboard" | cut -c1-64)
  [ -n "$want" ] && [ "$want" = "$live" ] && ok "switchboard: binary sha256 matches deploy/EXPECTED_SHA256" || bad "switchboard: binary differs (live ${live:0:12}, repo ${want:0:12})"
  gx "cat /etc/switchboard/config.json" | python3 -c '
import json,sys
live=json.load(sys.stdin); gen=json.load(open(sys.argv[1]))
same = live["tools"]==gen["tools"] and {a:v["tools"] for a,v in live["agents"].items()}=={a:v["tools"] for a,v in gen["agents"].items()}
print("PASS  switchboard: live tools and agent allow-lists == generated/agents.json" if same else "FAIL  switchboard: live config differs from generated/agents.json")
sys.exit(0 if same else 1)' "$ROOT/switchboard/generated/agents.json" || FAILS=$((FAILS+1))
  # v0.4: on the tailnet as tag:switchboard, and serve publishes only the passkey page.
  out=$(gx "tailscale status --json" | python3 -c 'import json,sys; s=json.load(sys.stdin)["Self"]; print("ok" if s.get("Online") and (s.get("Tags") or [])==["tag:switchboard"] else "bad")' 2>/dev/null)
  [ "$out" = ok ] && ok "switchboard: tailscale online as tag:switchboard" || bad "switchboard: tailscale not online as tag:switchboard"
  out=$(gx "tailscale serve status --json" | python3 -c 'import json,sys; s=json.load(sys.stdin); w=s.get("Web",{}); print("ok" if list(s.get("TCP",{}))==["443"] and [h for v in w.values() for h in v["Handlers"].values()]==[{"Proxy":"http://127.0.0.1:8801"}] else "bad")' 2>/dev/null)
  [ "$out" = ok ] && ok "switchboard: serve 443 -> 127.0.0.1:8801 only" || bad "switchboard: serve config is not exactly 443 -> 127.0.0.1:8801"
}

case "${1:-}" in
  --all) "$ROOT/boxes/coder/bin/drift-check.sh" || FAILS=$((FAILS+1)); for b in "${JOBS[@]}"; do check_job "$b"; done; check_job_providers; check_switchboard ;;
  switchboard) check_switchboard ;;
  coder) exec "$ROOT/boxes/coder/bin/drift-check.sh" ;;
  homebot) check_job "$1"; check_job_providers ;;
  *) echo "usage: $0 --all | coder | homebot | switchboard" >&2; exit 2 ;;
esac
[ "$FAILS" -eq 0 ] && echo "DRIFT-CHECK ALL: CLEAN" || { echo "DRIFT-CHECK ALL: $FAILS failing"; exit 1; }
