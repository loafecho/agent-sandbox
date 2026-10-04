#!/bin/bash
# Lives in the box at ~/.coder-box/services.sh; /opt/coder/boot.sh runs it at every box start.
# B4: Claude Code Remote Control for the work folder, in its own tmux server, in a restart loop.
. /opt/coder/profile.sh
# Non-secret env for every chat the rc loop spawns. A live box can't take `--env` (create-time only in
# OpenShell 0.1.1), so it lives here. Credentials never go here: they are providers (openshell/providers.tsv).
export CLOUDFLARE_ACCOUNT_ID=your-cloudflare-account-id   # an id, not a credential
export WRANGLER_SEND_METRICS=false
cd "$HOME/work" || exit 1
tmux -L rc kill-server 2>/dev/null
tmux -L rc new-session -d -s rc 'while :; do claude rc --spawn=same-dir; echo "claude rc exited rc=$? at $(date -u +%FT%TZ)"; sleep 15; done'
echo "$(date -u +%FT%TZ) services started: rc"
