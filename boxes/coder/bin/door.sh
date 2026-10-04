#!/usr/bin/env bash
# Open or close one named door from openshell/doors.tsv on the live box `coder`.
#   door.sh NAME               dry run (the gateway validates the change, nothing is applied)
#   door.sh NAME --yes-write   open it. Only after the operator approved this door by name.
#   door.sh NAME --close --yes-write   remove the rule
# Never use `openshell rule approve-all`: the standing check itself drafts pending rules for Infisical,
# pve1 and the LAN, and approve-all would open them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
NAME="${1:?usage: door.sh NAME [--close] [--yes-write]}"; shift
WRITE=0; CLOSE=0
for a in "$@"; do case "$a" in --yes-write) WRITE=1;; --close) CLOSE=1;; *) echo "unknown arg $a"; exit 2;; esac; done
row="$(grep -P "^$NAME\t" "$HERE/openshell/doors.tsv")" || { echo "no door named $NAME in doors.tsv"; exit 2; }
IFS=$'\t' read -r _ binary endpoints <<<"$row"
if ((CLOSE)); then
  args=()
else
  args=(policy update coder --rule-name "$NAME" --binary "$binary")
  IFS=',' read -ra eps <<<"$endpoints"
  for e in "${eps[@]}"; do args+=(--add-endpoint "$e"); done
fi
if ((CLOSE)); then args=(policy update coder --remove-rule "$NAME"); fi
if ((WRITE)); then args+=(--wait); else args+=(--dry-run); fi
echo "openshell ${args[*]}"
osh "${args[@]}"
if ((WRITE)); then echo "applied: re-capture with bin/drift-check.sh --capture and commit"; else echo "dry run: nothing applied"; fi
