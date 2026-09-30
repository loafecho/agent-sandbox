#!/usr/bin/env bash
# The operator runs this. Loads Homebot's two tokens from its own Infisical project (env prod) into OpenShell
# providers on the agent host's jobs gateway: homebot-ha (HOMEBOT_HA_TOKEN) and homebot-claude (HOMEBOT_CLAUDE_TOKEN).
# Uses the operator's own `infisical login` session. Values travel on ssh stdin only: never on a command
# line, in history, or in a log. Re-run after rotating either token.
#   HOMEBOT_INFISICAL_PROJECT=<project id> bin/set-homebot-tokens.sh
set -uo pipefail
# Target: the jobs gateway's user on the agent host. Override both for another host.
OS_SSH_ARGS="${OS_SSH_ARGS:--o BatchMode=yes -i $HOME/.ssh/id_agent_host admin@172.16.0.32}"; OS_USER="${OS_USER:-openshell-jobs}"
PID="${HOMEBOT_INFISICAL_PROJECT:?set HOMEBOT_INFISICAL_PROJECT to the Homebot project id}"
LOG="$HOME/.cache/homebot-token.log"; mkdir -p "$(dirname "$LOG")"
load(){ # provider type envvar secret-name
  infisical secrets get "$4" --projectId "$PID" --env prod --plain --silent 2>/dev/null | head -1 | tr -d '[:space:]' |
  ssh $OS_SSH_ARGS "sudo -u $OS_USER -H sh -c 'cd; read -r $3 || true; [ -n \"\$$3\" ] || { echo \"$4 empty\"; exit 1; }; export $3;
    if openshell provider list 2>/dev/null | grep -q \"^$1 \"; then openshell provider update $1 --credential $3;
    else openshell provider create --name $1 --type $2 --credential $3; fi'"
  echo "$1 rc=$?"
}
{
  echo "run $(date -u +%FT%TZ)"
  [ "${HOMEBOT_ONLY:-ha}" = claude ] || load homebot-ha homebot-home-assistant HOMEBOT_HA_TOKEN HOMEBOT_HA_TOKEN
  [ "${HOMEBOT_ONLY:-claude}" = ha ] || load homebot-claude claude-code-oauth CLAUDE_CODE_OAUTH_TOKEN HOMEBOT_CLAUDE_TOKEN
  ssh $OS_SSH_ARGS 'sudo -u '"$OS_USER"' -H sh -c "cd; openshell provider list"'
} > "$LOG" 2>&1
cat "$LOG"
