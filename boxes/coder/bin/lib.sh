# shellcheck shell=bash
# Shared by the coder-box scripts. Sourced, not run. Runs on workstation until B10 removes the bootstrap key.
AGENT_HOST="${AGENT_HOST:-admin@172.16.0.32}"
AGENT_HOST_KEY="${AGENT_HOST_KEY:-$HOME/.ssh/id_agent_host}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -i "$AGENT_HOST_KEY")
OUT="${CODER_BOX_OUT:-$HOME/.cache/coder-box}"
mkdir -p "$OUT"

# hsh 'remote shell text'  -> runs on agent-host as the admin user (sudo available)
hsh() { ssh "${SSH_OPTS[@]}" "$AGENT_HOST" "$@"; }

# osh arg...  -> `openshell arg...` on agent-host as the openshell user, from its home
osh() {
  local q; q=$(printf '%q ' "$@")
  # -n: openshell exec waits forever on an open stdin (found 2026-10-04)
  ssh -n "${SSH_OPTS[@]}" "$AGENT_HOST" "sudo -u openshell -H sh -c 'cd && exec openshell $q'"
}

# box NAME 'shell text' [timeout]  -> runs inside the box as the box user, login env from /opt/coder/profile.sh
box() {
  local name="$1" text="$2" t="${3:-120}"
  # base64 keeps any quoting in $text intact through ssh, sudo and sh (a quoted curl format broke once)
  local b; b=$(printf '%s' ". /opt/coder/profile.sh; $text" | base64 -w0)
  osh sandbox exec -n "$name" --no-tty --no-login-shell --timeout "$t" -- bash -c "echo $b | base64 -d | bash"
}

ok()   { printf 'PASS  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; FAILS=$((${FAILS:-0}+1)); }
note() { printf '      %s\n' "$*"; }
