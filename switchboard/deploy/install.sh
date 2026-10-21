#!/usr/bin/env bash
# Install or update the switchboard on its VM (VM 160 by default), from an admin workstation. The VM has no SSH:
# everything goes through the Proxmox host's QEMU guest agent (`qm guest exec 160`), which runs as root in the VM.
#   install.sh     build config from generated/agents.json + token sha256s, push binary/config/CA/units/firewall
#                  (and the discord4 refresher), restart, print the live binary sha256 and write it to deploy/EXPECTED_SHA256
#                  v0.4: also Tailscale (pinned static build, --netfilter-mode=off, tag:switchboard, hostname switchboard),
#                  joined once with a one-time auth key left in /etc/switchboard/ts-authkey (deleted after), and
#                  `tailscale serve` 443 -> 127.0.0.1:8801 (the passkey page).
# The backend keys are not touched here: /etc/switchboard/secrets.env (root, 0600) must already exist on the VM,
# written from the secrets manager by a separate step. Site values (addresses, Discord ids, the approver's phone)
# come from the SB_* environment variables below; the defaults are documentation addresses.
# A staging build (cargo --features staging: fake Discord/backends, RP localhost) is refused.
# Never prints a token. guest-exec stdin is capped at 1 MiB, so files go up as base64 in chunks.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PVE_HOST="${PVE_HOST:-root@pve1}"
VMID="${SWITCHBOARD_VMID:-160}"
BIN="$HERE/target/x86_64-unknown-linux-musl/release/switchboard"
UP=/tmp/sb-up
TS_VER=1.104.1
TS_SHA=108d1d96ecf410d305571e173516f27038f870919a9b89c914a167c6d33a4528   # pkgs.tailscale.com/stable/tailscale_1.104.1_amd64.tgz.sha256
TS_TGZ="$HOME/.cache/switchboard-ts/tailscale_${TS_VER}_amd64.tgz"

# gx [--stdin FILE] CMD: run CMD (sh -c, as root) in the VM; print its stdout; exit with its exit code.
gx() {
  local in=/dev/null pass=()
  if [ "$1" = "--stdin" ]; then in="$2"; pass=(--pass-stdin 1); shift 2; fi
  local q; q=$(printf '%q' "$1")
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$PVE_HOST" "qm guest exec $VMID ${pass[*]} --timeout ${GX_TIMEOUT:-120} -- sh -c $q" <"$in" |
    python3 -c 'import json,sys
d=json.load(sys.stdin); sys.stdout.write(d.get("out-data","")); sys.stderr.write(d.get("err-data",""))
sys.exit(d.get("exitcode",1) if d.get("exited",1) else 124)'
}

# push LOCAL NAME: copy a file into $UP/NAME on the VM, 700 KB of base64 at a time.
push() {
  local chunks; chunks=$(mktemp -d)
  base64 -w0 "$1" | split -b 700000 - "$chunks/c."
  for c in "$chunks"/c.*; do gx --stdin "$c" "cat >> $UP/$2.b64"; done
  gx "base64 -d $UP/$2.b64 > $UP/$2 && rm $UP/$2.b64"
  rm -rf "$chunks"
}

[ -x "$BIN" ] || { echo "build first: CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl"; exit 1; }
BUILD_LINE=$("$BIN" version)
[ "$BUILD_LINE" = "switchboard $(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/Cargo.toml") build=production" ] || { echo "REFUSED: not a production build ($BUILD_LINE)"; exit 1; }
if [ ! -f "$TS_TGZ" ]; then mkdir -p "$(dirname "$TS_TGZ")"; curl -fsS -m 300 -o "$TS_TGZ" "https://pkgs.tailscale.com/stable/tailscale_${TS_VER}_amd64.tgz"; fi
echo "$TS_SHA  $TS_TGZ" | sha256sum -c --quiet || { echo "tailscale tarball sha256 mismatch"; exit 1; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
python3 - "$HERE/generated/agents.json" "$WORK/config.json" <<'PY'
import json, os, sys, pathlib
E = os.environ.get
gen = json.load(open(sys.argv[1]))
agents = {}
for name, a in gen["agents"].items():
    p = pathlib.Path(os.environ.get("SB_TOKEN_DIR", pathlib.Path.home() / ".config/switchboard")) / f"switchboard-{name}.sha256"
    h = p.read_text().split()[0].strip()
    assert len(h) == 64, f"{p}: not a sha256"
    agents[name] = {"token_sha256": h, "tools": a["tools"], "rate_per_min": a["rate_per_min"]}
cfg = {"listen": "0.0.0.0:8800", "allowed_sources": [E("SB_AGENT_HOST", "172.16.0.32")], "prometheus": E("SB_PROMETHEUS", "http://172.16.0.29:9090"),
       "pve": {"base": E("SB_PVE_API", "https://172.16.0.88:8006/api2/json"), "node": E("SB_PVE_NODE", "pve1"), "ca_file": "/etc/switchboard/pve-root-ca.pem"},
       "jellyfin": E("SB_JELLYFIN", "http://172.16.0.91:8096"),
       # Approve tier: one Discord channel; only the approver's own reaction counts.
       "approvals": {"guild": E("SB_DISCORD_GUILD", "100000000000000003"), "channel": E("SB_DISCORD_CHANNEL", "100000000000000004"),
                     "approver": E("SB_DISCORD_APPROVER", "100000000000000001"),
                     "window_secs": 1800, "max_pending": 3, "state_file": "/var/lib/switchboard/requests.json"},
       "power_vmids": gen.get("power_vmids", []),
       # v0.4: forwarded tools' gateways (each backend's token_env), the passkey page, the phone push.
       "backends": gen.get("backends", {}),
       # allow_src: the approver's phone's tailnet addresses, as tailscale serve reports them in X-Forwarded-For (serve answers 443
       # inside tailscaled, so the VM firewall alone cannot keep other tailnet devices off the page).
       "web": {"listen": "127.0.0.1:8801", "allow_src": E("SB_PHONE_IPS", "198.51.100.24,2001:db8::24").split(","),
               "rp_id": E("SB_RP_ID", "switchboard.tailnet.example"), "origin": "https://" + E("SB_RP_ID", "switchboard.tailnet.example"),
               "credentials_file": "/var/lib/switchboard/credentials.json", "enroll_file": "/etc/switchboard/enroll.json"},
       "ntfy": {"url": E("SB_NTFY_URL", "https://ntfy.tailnet.example"), "topic": "approvals", "pin_ip": E("SB_NTFY_IP", "198.51.100.96")},
       "audit_log": "/var/lib/switchboard/audit.jsonl", "agents": agents, "tools": gen["tools"]}
for name, a in gen["agents"].items():
    for k in ("forward", "eval"):
        if k in a:
            agents[name][k] = a[k]
json.dump(cfg, open(sys.argv[2], "w"), indent=1, sort_keys=True)
PY
# The only CA the switchboard trusts for Proxmox: the cluster's own CA, read straight from the Proxmox host.
ssh -o BatchMode=yes "$PVE_HOST" cat /etc/pve/pve-root-ca.pem >"$WORK/pve-root-ca.pem"
grep -q 'BEGIN CERTIFICATE' "$WORK/pve-root-ca.pem" || { echo "could not read the cluster's pve-root-ca.pem"; exit 1; }
WANT=$(sha256sum "$BIN" | cut -c1-64)

cat >"$WORK/remote.sh" <<EOF
set -e
# The one-time Tailscale key never outlives this script, whatever fails (SEC-6, round 2).
trap 'rm -f /etc/switchboard/ts-authkey' EXIT
cd $UP
echo "$WANT  switchboard" | sha256sum -c --quiet
chmod 0700 switchboard
[ "\$(./switchboard version)" = "$BUILD_LINE" ] || { echo "REFUSED on the VM: not the production build"; exit 1; }
[ -s /etc/switchboard/secrets.env ] || { echo "no /etc/switchboard/secrets.env: write the backend keys first"; exit 1; }
id switchboard >/dev/null 2>&1 || useradd --system --home /var/lib/switchboard --shell /usr/sbin/nologin switchboard
install -d -o switchboard -g switchboard -m 0750 /var/lib/switchboard
install -d -o root -g switchboard -m 0750 /etc/switchboard
install -o root -g root -m 0755 switchboard /usr/local/bin/switchboard.new
mv -f /usr/local/bin/switchboard.new /usr/local/bin/switchboard
install -o root -g switchboard -m 0640 config.json /etc/switchboard/config.json
install -o root -g switchboard -m 0644 pve-root-ca.pem /etc/switchboard/pve-root-ca.pem
install -o root -g root -m 0644 switchboard.service /etc/systemd/system/switchboard.service
install -o root -g root -m 0755 switchboard-discord-ips /usr/local/sbin/switchboard-discord-ips
install -o root -g root -m 0644 switchboard-discord-ips.service /etc/systemd/system/switchboard-discord-ips.service
install -o root -g root -m 0644 switchboard-discord-ips.timer /etc/systemd/system/switchboard-discord-ips.timer
nft -c -f nftables.conf
install -o root -g root -m 0644 nftables.conf /etc/nftables.conf
rm -f /etc/nftables.d/bootstrap.nft
# Tailscale: pinned static build, our own unit flags (no netfilter rules of its own, no DNS takeover).
if [ -f tailscale.tgz ]; then
  tar xzf tailscale.tgz
  install -o root -g root -m 0755 tailscale_${TS_VER}_amd64/tailscaled /usr/sbin/tailscaled
  install -o root -g root -m 0755 tailscale_${TS_VER}_amd64/tailscale /usr/bin/tailscale
  rm -rf tailscale_${TS_VER}_amd64 tailscale.tgz
fi
install -o root -g root -m 0644 tailscaled.service /etc/systemd/system/tailscaled.service
install -d -m 0700 /var/lib/tailscale
systemctl daemon-reload
systemctl restart nftables
systemctl enable --now tailscaled >/dev/null 2>&1
for i in 1 2 3 4 5 6 7 8 9 10; do tailscale status --json >/dev/null 2>&1 && break; tailscale status 2>&1 | grep -q 'Logged out\|NeedsLogin' && break; sleep 1; done
if ! tailscale status --json 2>/dev/null | grep -q '"BackendState": "Running"'; then
  [ -s /etc/switchboard/ts-authkey ] || { echo "tailscale: not joined and no /etc/switchboard/ts-authkey (put a one-time auth key there first)"; exit 1; }
  timeout 90 tailscale up --auth-key=file:/etc/switchboard/ts-authkey --hostname=switchboard --advertise-tags=tag:switchboard \
    --netfilter-mode=off --accept-dns=false --accept-routes=false --ssh=false
fi
rm -f /etc/switchboard/ts-authkey
tailscale serve --bg --https=443 http://127.0.0.1:8801 >/dev/null
systemctl start switchboard-discord-ips.service
systemctl enable --now switchboard-discord-ips.timer >/dev/null 2>&1
systemctl enable switchboard >/dev/null 2>&1
systemctl restart switchboard
sleep 2
systemctl is-active switchboard
runuser -u switchboard -- /usr/local/bin/switchboard check-config --config /etc/switchboard/config.json
cd / && rm -rf $UP
echo "live sha256: \$(sha256sum /usr/local/bin/switchboard | cut -c1-64)"
tailscale status --json | python3 -c 'import json,sys; s=json.load(sys.stdin)["Self"]; print("tailscale:", s["HostName"], s["DNSName"], ",".join(s.get("Tags") or []), "online" if s.get("Online") else "OFFLINE", ",".join(s["TailscaleIPs"]))' 2>/dev/null \
  || tailscale status --json | grep -E '"(HostName|DNSName|Online)"' | head -4
echo "serve: \$(tailscale serve status --json | tr -d '\n ' )"
EOF

gx "rm -rf $UP && mkdir -m 0700 $UP"
push "$BIN" switchboard
push "$WORK/config.json" config.json
push "$WORK/pve-root-ca.pem" pve-root-ca.pem
push "$HERE/deploy/switchboard.service" switchboard.service
push "$HERE/deploy/nftables.conf" nftables.conf
for f in switchboard-discord-ips switchboard-discord-ips.service switchboard-discord-ips.timer; do push "$HERE/deploy/$f" "$f"; done
push "$HERE/deploy/tailscaled.service" tailscaled.service
if [ "$(gx "/usr/sbin/tailscaled --version 2>/dev/null | head -1" || true)" != "$TS_VER" ]; then push "$TS_TGZ" tailscale.tgz; fi
push "$WORK/remote.sh" remote.sh
OUT=$(GX_TIMEOUT=400 gx "TS_VER=$TS_VER sh $UP/remote.sh")
echo "$OUT"
LIVE=$(echo "$OUT" | sed -n 's/^live sha256: //p')
echo "$WANT" >"$HERE/deploy/EXPECTED_SHA256"
echo "EXPECTED_SHA256: $(cat "$HERE/deploy/EXPECTED_SHA256")"
if [ "$LIVE" = "$WANT" ]; then echo "DEPLOY OK: live binary == deploy/EXPECTED_SHA256"; else echo "DEPLOY MISMATCH"; exit 1; fi
