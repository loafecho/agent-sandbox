#!/usr/bin/env bash
# B2 proofs on the long-lived box `coder`. One mode per proof:
#   --size                 1. cpus / memory / disk inside the box (read only)
#   --persist --yes-write  2. marker files, stop the box, start it, see what survived
#   --after-reboot         3. after a VM reboot: is the box Ready with no hand on it (read only)
#   --loop-deny            5a. call a harmless site from the box: must be refused, and a pending rule must appear
#   --loop-open            5b. after the operator approved the rule: the call works, and the standing check passes
#                              with that site as the allowed-host control (this is also proof 4)
#   --loop-closed          5c. after the rule was removed: the call is refused again
# Approving and removing the rule is never done by this script: that is the operator's line.
# Output is also saved under ~/.cache/coder-box/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
NAME=coder; FAILS=0; MODE="${1:-}"; WRITE=0; [[ "${2:-}" == "--yes-write" ]] && WRITE=1
SITE="${LOOP_SITE:-https://example.org/}"
main() {
echo "prove-box $(date -u +%FT%TZ) mode=$MODE"

case "$MODE" in
--size)
  s="$(box "$NAME" 'echo "$(nproc) $(free -m | awk "/Mem:/{print \$2}") $(df -BG --output=avail /home/coder | tail -1 | tr -dc 0-9) $(uname -r) $(id -u) $HOME"' | tail -1)"
  read -r cpus mem disk kern uid home <<<"$s"
  echo "cpus=$cpus mem_mb=$mem home_free_gb=$disk kernel=$kern uid=$uid home=$home"
  [[ "${cpus:-0}" -ge 4 ]] && ok "cpus >= 4" || bad "cpus=$cpus (want 4)"
  [[ "${mem:-0}" -ge 7500 ]] && ok "memory >= 7.5 GB" || bad "memory=${mem} MB (want about 8 GB)"
  [[ "${disk:-0}" -ge 30 ]] && ok "home has >= 30 GB free" || bad "home free=${disk} GB (want 30)"
  [[ "$home" == /home/coder ]] && ok "HOME is /home/coder" || bad "HOME is $home"
  ;;
--persist)
  if ! ((WRITE)); then echo "WOULD write markers in ~ /tmp /sandbox, then openshell sandbox stop $NAME and start $NAME, then read them back"; exit 0; fi
  tok="m$(date +%s)"
  box "$NAME" "echo $tok > ~/.coder-box/marker; echo $tok > /tmp/marker; echo $tok > /sandbox/marker; sleep 12; echo $tok > ~/.coder-box/marker-late; wc -l < ~/.coder-box/boot.log" | tail -1 > "$OUT/boots-before"
  osh sandbox stop "$NAME"; osh sandbox list
  osh sandbox start "$NAME"; osh sandbox list
  r="$(box "$NAME" 'echo "home=$(cat ~/.coder-box/marker 2>/dev/null) late=$(cat ~/.coder-box/marker-late 2>/dev/null) tmp=$(cat /tmp/marker 2>/dev/null) sandbox=$(cat /sandbox/marker 2>/dev/null) boots=$(wc -l < ~/.coder-box/boot.log)"' | tail -1)"
  echo "token=$tok boots_before=$(cat "$OUT/boots-before") after: $r"
  grep -q "home=$tok" <<<"$r" && ok "the home marker survived a stop and start" || bad "the home marker is gone: /home/coder does not persist"
  grep -q "late=$tok" <<<"$r" && note "a write made 1 second before the stop survived too" || note "a write made 1 second before the stop was lost (a stop is a hard kill; boot.sh flushes every 5 s)"
  grep -q "sandbox=$tok" <<<"$r" && note "/sandbox marker survived" || note "/sandbox marker gone"
  grep -q "tmp=$tok" <<<"$r" && note "/tmp marker survived" || note "/tmp marker gone (expected for a tmpfs)"
  ;;
--after-reboot)
  hsh 'uptime -s'
  line="$(osh sandbox list | grep -E "^\s*$NAME\b" || true)"; echo "$line"
  grep -q -i ready <<<"$line" && ok "box $NAME is Ready after the reboot with no manual step" || bad "box $NAME is not Ready after the reboot (install systemd/coder-box.service and reboot again)"
  box "$NAME" 'tail -2 ~/.coder-box/boot.log' || true
  ;;
--loop-deny)
  r="$(box "$NAME" "curl -s -m 10 -o /dev/null -w '%{http_code}' $SITE; echo" | tail -1)"
  [[ "$r" == 000 ]] && ok "$SITE is refused from the box" || bad "$SITE answered ($r) with no rule"
  box "$NAME" 'command -v openshell >/dev/null && echo "openshell CLI present in box" || echo "no openshell CLI in the box"' | tail -1
  echo "--- pending rules (the operator approves one with: openshell rule approve --chunk-id <id> $NAME)"
  osh rule get "$NAME" --status pending
  ;;
--loop-open)
  r="$(box "$NAME" "curl -s -m 10 -o /dev/null -w '%{http_code}' $SITE; echo" | tail -1)"
  [[ "$r" =~ ^[23] ]] && ok "$SITE answers after approval ($r)" || bad "$SITE still refused after approval ($r)"
  box "$NAME" "/opt/coder/box-deny-check.sh --box --control $SITE" 300; rc=$?
  [[ $rc -eq 0 ]] && ok "standing check passed on box $NAME with its allowed-host control" || bad "standing check rc=$rc"
  hsh 'sudo -u coder bash -s -- --host' < "$HERE/bin/box-deny-check.sh" | tail -3; rc=${PIPESTATUS[0]}
  [[ $rc -eq 0 ]] && ok "host control: Infisical and Home Assistant answer from the VM" || bad "host control rc=$rc"
  ;;
--loop-closed)
  r="$(box "$NAME" "curl -s -m 10 -o /dev/null -w '%{http_code}' $SITE; echo" | tail -1)"
  [[ "$r" == 000 ]] && ok "$SITE is refused again after the rule was removed" || bad "$SITE still answers ($r)"
  osh policy get "$NAME" 2>&1 | sed -n 1,40p
  ;;
*) sed -n 2,11p "$0"; exit 2;;
esac
echo "$FAILS failure(s)"; exit $((FAILS>0))
}
main 2>&1 | tee "$OUT/prove-box-$(date -u +%Y%m%dT%H%M%SZ).log"
exit "${PIPESTATUS[0]}"
