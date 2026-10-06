#!/usr/bin/env bash
# Restart the coder box's Remote Control loop inside the box (re-runs ~/.coder-box/services.sh), then show it.
# Needed after attaching or changing a provider, or after changing services.sh: chats that are
# already open keep their old env. Ends the rc loop's own chats; other tmux servers in the box are untouched.
#   bin/restart-rc.sh             show state only (read-only)
#   bin/restart-rc.sh --yes-write restart, then show state
# Fully detached (setsid -f, all fds closed) because a plain `sandbox exec` waits on the child and hangs.
# If the capture shows "Enable Remote Control? (y/n)", that answer is the operator's: bin/connect, then
# `tmux -L rc attach -t rc` (leave with Ctrl-b d, never Ctrl-C).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
if [ "${1:-}" = "--yes-write" ]; then
  box coder 'setsid -f bash -c "bash ~/.coder-box/services.sh >/tmp/services-restart.log 2>&1" </dev/null >/dev/null 2>&1; echo restart started' 30
  for _ in $(seq 1 15); do
    box coder 'tmux -L rc capture-pane -p -t rc 2>/dev/null | grep -q -E "Capacity|Enable Remote Control"' 20 && break
    sleep 2
  done
fi
box coder 'cat /tmp/services-restart.log 2>/dev/null | tail -1; tmux -L rc ls; tmux -L rc show-environment -g | grep -E "^(CLOUDFLARE_ACCOUNT_ID|WRANGLER_SEND_METRICS)=" | sed "s/=.*/ set/"; tmux -L rc capture-pane -p -t rc | grep -E "Capacity|Enable Remote Control" | head -2' 40
