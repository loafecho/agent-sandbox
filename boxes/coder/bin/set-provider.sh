#!/usr/bin/env bash
# The operator runs this. Loads one provider's credential from Infisical into the OpenShell gateway on agent-host,
# creating the provider or updating it in place. Row comes from openshell/providers.tsv.
# Uses the operator's own `infisical login`. The value travels on ssh stdin only: never on a command line,
# in history, in a log, or on screen. Re-run after rotating the secret in Infisical.
#   bin/set-provider.sh NAME            load (create or update)
#   bin/set-provider.sh NAME --attach   load, then attach to the row's box (new processes get it;
#                                       restart the rc loop afterwards: bin/restart-rc.sh --yes-write)
# Same shape as boxes/homebot/bin/set-homebot-tokens.sh.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
NAME="${1:?usage: set-provider.sh NAME [--attach]}"; ATTACH="${2:-}"
TSV="$HERE/openshell/providers.tsv"
PID=$(sed -n 's/^# infisical_project: *//p' "$TSV")
[ -n "$PID" ] && [ "${PID#TBD}" = "$PID" ] || { echo "!! infisical_project not set in providers.tsv"; exit 2; }
row=$(grep -v '^#' "$TSV" | awk -F'\t' -v n="$NAME" '$1==n') || true
[ -n "$row" ] || { echo "!! no provider named $NAME in providers.tsv"; exit 2; }
IFS=$'\t' read -r _ TYPE VAR SECRET BOXNAME <<<"$row"
infisical user get token --plain >/dev/null 2>&1 || { echo "!! not logged in to Infisical (run: infisical login)"; exit 1; }
LOG="$HOME/.cache/coder-box/set-provider.log"; mkdir -p "$(dirname "$LOG")"
{
  echo "run $(date -u +%FT%TZ) $NAME ($TYPE, $VAR <- infisical $SECRET)"
  infisical secrets get "$SECRET" --projectId "$PID" --env prod --plain --silent 2>/dev/null | head -1 | tr -d '[:space:]' |
  ssh "${SSH_OPTS[@]}" "$AGENT_HOST" "sudo -u openshell -H sh -c 'cd; read -r $VAR || true; [ -n \"\$$VAR\" ] || { echo \"$SECRET empty in Infisical\"; exit 1; }; export $VAR;
    if openshell provider list 2>/dev/null | grep -q \"^$NAME \"; then openshell provider update $NAME --credential $VAR;
    else openshell provider create --name $NAME --type $TYPE --credential $VAR; fi' >/dev/null"
  echo "$NAME load rc=$?"
  if [ "$ATTACH" = "--attach" ]; then
    osh sandbox provider attach "$BOXNAME" "$NAME" --wait --timeout 120 >/dev/null 2>&1
    echo "$NAME attach to $BOXNAME rc=$?"
  fi
  osh provider list
  osh sandbox provider list "$BOXNAME"
} > "$LOG" 2>&1
cat "$LOG"
