#!/usr/bin/env bash
# B1 proofs, on a throwaway box (`boxtest`, created by create-box.sh --test):
#   1. the box boots and its kernel differs from the VM's
#   2. the standing check passes inside the box, with both controls
#   3. `coder` on the host can't read /var/lib/openshell and can't run the CLI against the gateway
#   4. (after a VM reboot) the gateway is up with no manual step  -> run with --after-reboot
# Reads only, except --cleanup which deletes the throwaway box. Output is also saved under ~/.cache/coder-box/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
NAME=boxtest; FAILS=0; MODE="${1:-}"
main() {
echo "prove-gateway $(date -u +%FT%TZ) mode=${MODE:-proofs}"

if [[ "$MODE" == "--cleanup" ]]; then osh sandbox delete "$NAME"; osh sandbox list; exit 0; fi

if [[ "$MODE" == "--after-reboot" ]]; then
  up="$(hsh 'uptime -s; U=$(id -u openshell); sudo -u openshell env XDG_RUNTIME_DIR=/run/user/$U systemctl --user is-active openshell-gateway; sudo -u openshell env XDG_RUNTIME_DIR=/run/user/$U systemctl --user show openshell-gateway -p ActiveEnterTimestamp --value')"
  echo "$up"
  grep -qx active <<<"$up" && ok "gateway is active after the reboot, no manual step" || bad "gateway is not active after the reboot"
  osh status 2>&1 | sed -n 1,8p
  echo "$FAILS failure(s)"; exit $((FAILS>0))
fi

hk="$(hsh 'uname -r')"; bk="$(box "$NAME" 'uname -r' 2>/dev/null | tail -1)"
echo "host kernel: $hk   box kernel: $bk"
[[ -n "$bk" && "$bk" != "$hk" ]] && ok "box kernel differs from the VM's" || bad "box kernel missing or same as the VM's"
box "$NAME" 'echo "cpus=$(nproc) mem_mb=$(free -m | awk "/Mem:/{print \$2}") root_free=$(df -h / | awk "NR==2{print \$4}") home_free=$(df -h /home/coder | awk "NR==2{print \$4}") uid=$(id -u) home=$HOME"' 2>&1 | tail -1

echo "--- standing check inside the box (control: api.github.com, allowed for curl in policy-test.yaml)"
box "$NAME" '/opt/coder/box-deny-check.sh --box --control https://api.github.com/zen' 300; rc=$?
[[ $rc -eq 0 ]] && ok "standing check passed inside the box" || bad "standing check rc=$rc inside the box"
echo "--- standing check control from the host as coder"
hsh 'sudo -u coder bash -s -- --host' < "$HERE/bin/box-deny-check.sh" | tail -4; rc=${PIPESTATUS[0]}
[[ $rc -eq 0 ]] && ok "host control: the secrets manager and Home Assistant answer from the VM" || bad "host control rc=$rc"
echo "--- what the box's own log recorded"
osh logs "$NAME" --since 10m --source sandbox -n 400 2>/dev/null | grep -E "NET:OPEN" | sed -E 's/.*NET:OPEN/NET:OPEN/' | awk '{print $3}' | sort | uniq -c

echo "--- coder on the host against the gateway"
j="$(hsh 'sudo -u coder sh -c "ls /var/lib/openshell 2>&1 | head -2; echo ls-rc=\$?; cd /tmp; timeout 20 openshell sandbox list </dev/null 2>&1 | head -3; echo ---direct; timeout 20 openshell --gateway-endpoint https://127.0.0.1:17670 --gateway-insecure sandbox list </dev/null 2>&1 | head -4; echo ---groups; id -nG"')"
echo "$j"
grep -q "Permission denied" <<<"$j" && ok "coder can't read /var/lib/openshell" || bad "coder can read /var/lib/openshell"
if sed '/^---groups/,$d' <<<"$j" | grep -q -E "^\s*(boxtest|coder)\b|Ready"; then bad "coder can list boxes through the gateway"; else ok "coder can't use the CLI against the gateway"; fi
grep -qw kvm <<<"$(tail -1 <<<"$j")" && bad "coder is in the kvm group" || ok "coder is not in the kvm group"
echo "$FAILS failure(s)"; exit $((FAILS>0))
}
main 2>&1 | tee "$OUT/prove-gateway-$(date -u +%Y%m%dT%H%M%SZ).log"
exit "${PIPESTATUS[0]}"
