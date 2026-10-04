#!/usr/bin/env bash
# B1/B2: create a box on agent-host from the coder-box rootfs tar.
#   create-box.sh --test [--yes-write]   throwaway box `boxtest` with policy-test.yaml (one control door)
#   create-box.sh [--yes-write]          the long-lived box `coder` with policy.yaml (no network rules)
# Default is a dry run: it checks every precondition and prints the exact create command.
# Rollback: openshell sandbox delete <name>  (bin/osh sandbox delete <name>)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
WRITE=0; TEST=0
for a in "$@"; do case "$a" in --yes-write) WRITE=1;; --test) TEST=1;; *) echo "unknown arg $a"; exit 2;; esac; done
TAG="${TAG:-0.1}"
if ((TEST)); then NAME=boxtest; POLICY=policy-test.yaml; else NAME=coder; POLICY=policy.yaml; fi
IMG="/var/lib/openshell/images/coder-box_${TAG}.tar"
RPOL="/var/lib/openshell/coder-box/$POLICY"
FAILS=0

state="$(hsh "id -u openshell 2>/dev/null; id -g openshell 2>/dev/null; sudo test -f $IMG && echo img-yes || echo img-no; sudo -u openshell -H sh -c 'cd; openshell sandbox list 2>&1' | head -20")" || true
U="$(sed -n 1p <<<"$state")"; G="$(sed -n 2p <<<"$state")"
[[ "$U" =~ ^[0-9]+$ ]] && ok "openshell user exists ($U/$G)" || bad "no openshell user on agent-host (run install-gateway.sh first)"
grep -q img-yes <<<"$state" && ok "image $IMG is on agent-host" || bad "image $IMG missing (run build-image.sh --yes-write)"
if [[ -f "$OUT/coder-box_${TAG}.tar" ]]; then
  built="$(docker run --rm "coder-box:${TAG}" cat /opt/coder-ids 2>/dev/null || true)"
  [[ "$built" == "$U $G" ]] && ok "image was built for ids $U/$G" || bad "image built for ids '$built' but openshell is $U/$G: rebuild"
fi
grep -q -E "^\s*$NAME\b" <<<"$state" && bad "a box named $NAME already exists" || ok "name $NAME is free"
python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$HERE/openshell/$POLICY" && ok "$POLICY parses"

CMD=(sandbox create --name "$NAME" --from "$IMG" --policy "$RPOL" --approval-mode manual --no-auto-providers --no-tty --detach -- /opt/coder/boot.sh)
echo "command: openshell ${CMD[*]}"
((FAILS)) && { echo "$FAILS precondition(s) failed"; ((WRITE)) && exit 1 || exit 0; }
if ! ((WRITE)); then echo "dry run: nothing created (--yes-write to create)"; exit 0; fi

hsh "sudo install -o openshell -g openshell -m 640 /dev/stdin $RPOL" < "$HERE/openshell/$POLICY"
# First boot after a new image takes about 4 minutes; keep the wait generous.
ssh "${SSH_OPTS[@]}" -o ServerAliveInterval=30 "$AGENT_HOST" "sudo -u openshell -H sh -c 'cd && timeout 900 openshell $(printf '%q ' "${CMD[@]}")'"
for _ in $(seq 1 90); do
  line="$(osh sandbox list 2>/dev/null | grep -E "^\s*$NAME\b" || true)"
  grep -q -i ready <<<"$line" && { echo "$line"; ok "box $NAME is Ready"; exit 0; }
  grep -q -i -E "error|failed" <<<"$line" && { echo "$line"; bad "box $NAME failed"; osh logs "$NAME" -n 40 || true; exit 1; }
  sleep 10
done
bad "box $NAME not Ready after 15 minutes"; osh sandbox list; exit 1
