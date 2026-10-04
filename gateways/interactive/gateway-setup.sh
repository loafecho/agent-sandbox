#!/usr/bin/env bash
# Host half of B1 (boxes/coder/bin/install-gateway.sh copies it over). Runs ON the agent host as root.
# Installs OpenShell 0.1.1, the `openshell` system user, the gateway user service and the CLI
# registration. Idempotent. Default is a dry run that changes nothing; --yes-write applies.
# Touches nothing that belongs to the `coder` user.
set -euo pipefail
WRITE=0; [[ "${1:-}" == "--yes-write" ]] && WRITE=1
HERE="$(cd "$(dirname "$0")" && pwd)"
DEB_URL="https://github.com/NVIDIA/OpenShell/releases/download/v0.1.1/openshell_0.1.1-1_amd64.deb"
DEB_SHA="2360c9eeb32ad015f67763eb220441f7008739fe88ba58ec7c28851dc64a3325"   # release asset digest
# sha256 of the binaries the .deb installs (recorded 2026-10-04 from two earlier installs)
declare -A BIN_SHA=(
  [/usr/bin/openshell]=c87942b492ca7f8bddc336ee289e3e881246b9a48e6f4cb74e17fffc863d1447
  [/usr/bin/openshell-gateway]=8b4065df621c2e35d8450e3a7b6d2afe3302e74718a25c095ca4bd15ebff3d00
  [/usr/libexec/openshell/openshell-driver-vm]=4bced997f8cfb0b9b33af4664619c54e7fd70952a0d717242e8cbf10930d45a4
)
OS_HOME=/var/lib/openshell
PORT=17670
changes=0
say(){ printf '%s\n' "$*"; }
act(){ changes=$((changes+1)); if ((WRITE)); then say "DO   $*"; "$@"; else say "WOULD $*"; fi; }
[[ $EUID -eq 0 ]] || { say "run as root"; exit 2; }
[[ -e /dev/kvm ]] || { say "FAIL: no /dev/kvm"; exit 1; }

# 1. user: kvm group only, real home and shell (the unit writes to %h), linger. coder stays out of kvm.
if ! id openshell >/dev/null 2>&1; then
  act useradd -r -m -d "$OS_HOME" -s /bin/sh -G kvm openshell
fi
if id openshell >/dev/null 2>&1; then
  id -nG openshell | tr ' ' '\n' | grep -qx kvm || act usermod -aG kvm openshell
  [[ "$(stat -c %a "$OS_HOME")" == 750 ]] || act chmod 750 "$OS_HOME"
  [[ "$(loginctl show-user openshell -p Linger --value 2>/dev/null)" == yes ]] || act loginctl enable-linger openshell
fi
if id -nG coder | tr ' ' '\n' | grep -qx kvm; then say "FAIL: coder is in the kvm group"; exit 1; fi

# 2. package: the release .deb, checksum first, then binaries compared with the recorded hashes.
if ! dpkg -s openshell 2>/dev/null | grep -q '^Version: 0.1.1-1$'; then
  if ((WRITE)); then
    changes=$((changes+1))
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    curl -fsSL -o "$tmp/openshell.deb" "$DEB_URL"
    echo "$DEB_SHA  $tmp/openshell.deb" | sha256sum -c - >/dev/null || { say "FAIL: .deb checksum"; exit 1; }
    say "DO   apt-get install openshell_0.1.1-1_amd64.deb (sha256 ok)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$tmp/openshell.deb" >/dev/null
  else
    changes=$((changes+1)); say "WOULD download $DEB_URL, check sha256 $DEB_SHA, apt-get install it"
  fi
fi
if command -v openshell >/dev/null; then
  for b in "${!BIN_SHA[@]}"; do
    got="$(sha256sum "$b" | cut -d' ' -f1)"
    [[ "$got" == "${BIN_SHA[$b]}" ]] || { say "FAIL: $b differs from the recorded hash ($got)"; exit 1; }
  done
  say "OK   binaries match the recorded hashes"
fi

# 3. config. sandbox_uid/gid are whatever `id openshell` prints here.
if id openshell >/dev/null 2>&1; then
  U="$(id -u openshell)"; G="$(id -g openshell)"
  CFG="$OS_HOME/.config/openshell"
  want_toml="$(sed "s/@UID@/$U/; s/@GID@/$G/" "$HERE/gateway.toml.tmpl")"
  [[ -d "$CFG" ]] || act install -d -o openshell -g openshell -m 775 "$OS_HOME/.config" "$CFG"
  if [[ "$(cat "$CFG/gateway.toml" 2>/dev/null)" != "$want_toml" ]]; then
    changes=$((changes+1))
    if ((WRITE)); then say "DO   write gateway.toml (sandbox_uid=$U sandbox_gid=$G)"; printf '%s\n' "$want_toml" | install -o openshell -g openshell -m 664 /dev/stdin "$CFG/gateway.toml"
    else say "WOULD write gateway.toml (sandbox_uid=$U sandbox_gid=$G)"; fi
  fi
  if [[ -f "$HERE/gateway.env" ]]; then   # optional extra environment for the gateway service
    cmp -s "$HERE/gateway.env" "$CFG/gateway.env" 2>/dev/null || act install -o openshell -g openshell -m 664 "$HERE/gateway.env" "$CFG/gateway.env"
  fi
  [[ -d "$OS_HOME/images" ]] || act install -d -o openshell -g openshell -m 750 "$OS_HOME/images"
  [[ -d "$OS_HOME/coder-box" ]] || act install -d -o openshell -g openshell -m 750 "$OS_HOME/coder-box"

  # 4. gateway as the openshell user's service.
  as_os(){ sudo -u openshell -H env XDG_RUNTIME_DIR="/run/user/$U" "$@"; }
  if ((WRITE)); then for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -S "/run/user/$U/bus" ]] && break; sleep 1; done; fi
  if [[ -S "/run/user/$U/bus" ]]; then
    as_os systemctl --user is-enabled -q openshell-gateway 2>/dev/null || act as_os systemctl --user enable openshell-gateway
    as_os systemctl --user is-active  -q openshell-gateway 2>/dev/null || act as_os systemctl --user start openshell-gateway
  else
    changes=$((changes+1)); say "WOULD enable and start openshell-gateway (user service of openshell)"
  fi

  # 5. CLI registration, copied from the gateway's own TLS folder.
  TLS="$OS_HOME/.local/state/openshell/tls"; REG="$CFG/gateways/openshell"
  if ((WRITE)); then for _ in $(seq 1 30); do [[ -f "$TLS/client/tls.key" ]] && break; sleep 1; done; fi
  if [[ -f "$TLS/client/tls.key" ]]; then
    if ! cmp -s "$TLS/client/tls.crt" "$REG/mtls/tls.crt" 2>/dev/null || [[ ! -f "$REG/metadata.json" ]]; then
      changes=$((changes+1))
      if ((WRITE)); then
        say "DO   register the CLI with the local gateway"
        install -d -o openshell -g openshell -m 700 "$CFG/gateways" "$REG" "$REG/mtls"
        install -o openshell -g openshell -m 600 "$TLS/ca.crt" "$TLS/client/tls.crt" "$TLS/client/tls.key" "$REG/mtls/"
        printf '{"name":"openshell","gateway_endpoint":"https://127.0.0.1:%s","is_remote":false,"gateway_port":0,"auth_mode":"mtls"}' "$PORT" \
          | install -o openshell -g openshell -m 664 /dev/stdin "$REG/metadata.json"
        printf 'openshell\n' | install -o openshell -g openshell -m 664 /dev/stdin "$CFG/active_gateway"
      else say "WOULD register the CLI with the local gateway"; fi
    fi
  else
    changes=$((changes+1)); say "WOULD register the CLI (gateway TLS folder not there yet)"
  fi
fi

say "---"
if ((WRITE)); then
  sleep 2
  ss -ltn | grep -q "127.0.0.1:$PORT " && say "OK   gateway listens on 127.0.0.1:$PORT" || { say "FAIL: nothing on 127.0.0.1:$PORT"; ss -ltnp | sed -n 1,20p; exit 1; }
  sudo -u openshell -H sh -c 'cd; openshell status' 2>&1 | sed -n 1,12p
fi
say "$changes change(s) $( ((WRITE)) && echo applied || echo 'pending (dry run)')"
