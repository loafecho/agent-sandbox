#!/usr/bin/env bash
# Second OpenShell install on the agent host, for throwaway job boxes (one fresh microVM per task; homebot here).
# Runs ON the agent host as root. Same shape as gateways/interactive/gateway-setup.sh, but for a separate user,
# home and port, so it never touches the interactive gateway (user openshell, port 17670). The two gateways'
# boxes are kept apart on the network by uid (jobs-wall.nft.in).
# Default is a dry run; --yes-write applies. Idempotent. Never removes the shared .deb or the openshell user.
set -euo pipefail
WRITE=0; [[ "${1:-}" == "--yes-write" ]] && WRITE=1
USR=openshell-jobs
OS_HOME=/var/lib/openshell-jobs
PORT=17680
changes=0
say(){ printf '%s\n' "$*"; }
act(){ changes=$((changes+1)); if ((WRITE)); then say "DO   $*"; "$@"; else say "WOULD $*"; fi; }
[[ $EUID -eq 0 ]] || { say "run as root"; exit 2; }
[[ -e /dev/kvm ]] || { say "FAIL: no /dev/kvm"; exit 1; }
dpkg -s openshell 2>/dev/null | grep -q '^Version: 0.1.1-1$' || { say "FAIL: openshell 0.1.1 .deb not installed (gateways/interactive/gateway-setup.sh installs it)"; exit 1; }
ss -ltn | grep -q "127.0.0.1:$PORT " && ! pgrep -u "$USR" -f openshell-gateway >/dev/null && { say "FAIL: port $PORT already taken by something else"; exit 1; }

# 1. user: own uid/gid, kvm group, real home and shell (forced-command ssh needs a shell), linger.
if ! id "$USR" >/dev/null 2>&1; then
  act useradd -r -m -d "$OS_HOME" -s /bin/sh -G kvm "$USR"
fi
if id "$USR" >/dev/null 2>&1; then
  id -nG "$USR" | tr ' ' '\n' | grep -qx kvm || act usermod -aG kvm "$USR"
  [[ "$(stat -c %a "$OS_HOME")" == 750 ]] || act chmod 750 "$OS_HOME"
  [[ "$(loginctl show-user "$USR" -p Linger --value 2>/dev/null)" == yes ]] || act loginctl enable-linger "$USR"
fi

# 2. config: sandbox uid/gid must equal this user's (else every box fails on /proc/self/status).
if id "$USR" >/dev/null 2>&1; then
  U="$(id -u "$USR")"; G="$(id -g "$USR")"
  CFG="$OS_HOME/.config/openshell"
  want_toml="[openshell]
version = 2

[openshell.drivers.vm]
allow_driver_config = true
# Job images are ~0.3-0.7 GB. Box size = driver defaults (2 vCPU, 2048 MiB, 4096 MiB).
rootfs_tar_max_bytes = 2147483648
sandbox_uid = $U
sandbox_gid = $G"
  want_env="OPENSHELL_TELEMETRY_ENABLED=false
OPENSHELL_COMPUTE_DRIVER=vm
OPENSHELL_GATEWAY_CONFIG=$CFG/gateway.toml
OPENSHELL_SERVER_PORT=$PORT"
  [[ -d "$CFG" ]] || act install -d -o "$USR" -g "$USR" -m 775 "$OS_HOME/.config" "$CFG"
  if [[ "$(cat "$CFG/gateway.toml" 2>/dev/null)" != "$want_toml" ]]; then
    changes=$((changes+1))
    if ((WRITE)); then say "DO   write gateway.toml (sandbox_uid=$U sandbox_gid=$G)"; printf '%s\n' "$want_toml" | install -o "$USR" -g "$USR" -m 664 /dev/stdin "$CFG/gateway.toml"
    else say "WOULD write gateway.toml (sandbox_uid=$U sandbox_gid=$G)"; fi
  fi
  if [[ "$(cat "$CFG/gateway.env" 2>/dev/null)" != "$want_env" ]]; then
    changes=$((changes+1))
    if ((WRITE)); then say "DO   write gateway.env (port $PORT)"; printf '%s\n' "$want_env" | install -o "$USR" -g "$USR" -m 664 /dev/stdin "$CFG/gateway.env"
    else say "WOULD write gateway.env (port $PORT)"; fi
  fi
  for d in images homebot; do
    [[ -d "$OS_HOME/$d" ]] || act install -d -o "$USR" -g "$USR" -m 750 "$OS_HOME/$d"
  done

  # 3. gateway as this user's systemd user service (the packaged unit reads %E/openshell/gateway.env).
  as_u(){ sudo -u "$USR" -H env XDG_RUNTIME_DIR="/run/user/$U" "$@"; }
  if ((WRITE)); then for _ in $(seq 1 15); do [[ -S "/run/user/$U/bus" ]] && break; sleep 1; done; fi
  if [[ -S "/run/user/$U/bus" ]]; then
    as_u systemctl --user is-enabled -q openshell-gateway 2>/dev/null || act as_u systemctl --user enable openshell-gateway
    as_u systemctl --user is-active  -q openshell-gateway 2>/dev/null || act as_u systemctl --user start openshell-gateway
  else
    changes=$((changes+1)); say "WOULD enable and start openshell-gateway (user service of $USR)"
  fi

  # 4. CLI registration for this user, pointing at its own port.
  TLS="$OS_HOME/.local/state/openshell/tls"; REG="$CFG/gateways/openshell"
  if ((WRITE)); then for _ in $(seq 1 20); do [[ -f "$TLS/client/tls.key" ]] && break; sleep 1; done; fi
  if [[ -f "$TLS/client/tls.key" ]]; then
    if [[ ! -f "$REG/metadata.json" ]] || ! grep -q "127.0.0.1:$PORT" "$REG/metadata.json"; then
      if ((WRITE)); then
        changes=$((changes+1)); say "DO   register the CLI with the jobs gateway"
        install -d -o "$USR" -g "$USR" -m 700 "$CFG/gateways" "$REG" "$REG/mtls"
        install -o "$USR" -g "$USR" -m 600 "$TLS/ca.crt" "$TLS/client/tls.crt" "$TLS/client/tls.key" "$REG/mtls/"
        printf '{"name":"openshell","gateway_endpoint":"https://127.0.0.1:%s","is_remote":false,"gateway_port":0,"auth_mode":"mtls"}' "$PORT" \
          | install -o "$USR" -g "$USR" -m 664 /dev/stdin "$REG/metadata.json"
        printf 'openshell\n' | install -o "$USR" -g "$USR" -m 664 /dev/stdin "$CFG/active_gateway"
      else changes=$((changes+1)); say "WOULD register the CLI with the jobs gateway"; fi
    fi
  else
    changes=$((changes+1)); say "WOULD register the CLI (gateway TLS folder not there yet)"
  fi
fi

say "---"
if ((WRITE)); then
  sleep 2
  ss -ltn | grep -q "127.0.0.1:$PORT " && say "OK   jobs gateway listens on 127.0.0.1:$PORT" || { say "FAIL: nothing on 127.0.0.1:$PORT"; exit 1; }
  ss -ltn | grep -q "127.0.0.1:17670 " && say "OK   interactive gateway still on 17670" || say "WARN: interactive gateway not listening on 17670"
  sudo -u "$USR" -H sh -c 'cd; openshell status' 2>&1 | sed -n 1,8p
fi
say "$changes change(s) $( ((WRITE)) && echo applied || echo 'pending (dry run)')"
