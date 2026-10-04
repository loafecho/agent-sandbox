#!/bin/bash
# The box's main process (the box has no systemd). Keeps the box alive and starts whatever
# ~/.coder-box/services.sh lists. That file lives in the persistent home, so adding a surface
# (B4 Remote Control, B5 Discord) needs no new image. v0 starts nothing.
. /opt/coder/profile.sh
mkdir -p "$HOME/.coder-box"
echo "$(date -u +%FT%TZ) boot kernel=$(uname -r) uid=$(id -u)" >> "$HOME/.coder-box/boot.log"
if [ -x "$HOME/.coder-box/services.sh" ]; then
  "$HOME/.coder-box/services.sh" >> "$HOME/.coder-box/services.log" 2>&1 &
fi
trap 'exit 0' TERM INT
# A box stop is a hard kill of the microVM: writes not yet flushed are lost (proved 2026-10-04,
# an unsynced marker vanished, a synced one survived). Flush every 5 seconds to keep that window small.
while :; do sleep 5 & wait $!; sync; done
