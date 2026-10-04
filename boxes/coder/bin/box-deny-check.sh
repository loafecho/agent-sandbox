#!/bin/bash
# The standing check: run after every rule change. No secrets, no writes. The target list below uses the
# example addresses from this repo; edit it to match your network.
#   --box  [--control URL]   run INSIDE the box: every target below must be REFUSED, and the control
#                            URL (an allowed host) must ANSWER. With no control the result is
#                            reported as "no control", which is not a pass.
#   --host                   run on the agent host as `coder`: the secrets manager and Home Assistant must ANSWER.
#                            This proves the checker can see an open door.
# A target counts as open only on positive evidence: an HTTP status line or an SSH banner.
# A bare TCP connect is not evidence either way (a transparent proxy can accept and then drop).
set -u
MODE=""; CONTROL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --box) MODE=box;;
    --host) MODE=host;;
    --control) CONTROL="$2"; shift;;
    *) echo "unknown arg $1"; exit 2;;
  esac
  shift
done
[ -n "$MODE" ] || { echo "usage: $0 --box [--control URL] | --host"; exit 2; }

http() {   # url -> "ANSWERED http=<code>" | "REFUSED curl-exit=<n>"
  local code rc
  code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null); rc=$?
  if [ -n "$code" ] && [ "$code" != "000" ]; then echo "ANSWERED http=$code"; else echo "REFUSED curl-exit=$rc"; fi
}
banner() { # host port -> "ANSWERED ssh-banner" | "REFUSED no-banner"
  local b
  b=$(timeout 8 bash -c "exec 3<>/dev/tcp/$1/$2 && head -c 4 <&3" 2>/dev/null)
  if [ "$b" = "SSH-" ]; then echo "ANSWERED ssh-banner"; else echo "REFUSED no-banner"; fi
}

# name|kind|target      kind: http = full URL, ssh = host:port
TARGETS='
unlisted site (example.com)|http|https://example.com/
unlisted site, plain http|http|http://example.com/
router|http|http://172.16.0.1/
workstation ssh (LAN)|ssh|172.16.0.54:22
hypervisor ssh (LAN)|ssh|172.16.0.88:22
hypervisor Proxmox UI (LAN)|http|https://172.16.0.88:8006/
agent host itself ssh (LAN)|ssh|172.16.0.32:22
workstation ssh (tailnet)|ssh|198.51.100.25:22
hypervisor ssh (tailnet)|ssh|198.51.100.4:22
hypervisor Proxmox UI (tailnet)|http|https://198.51.100.4:8006/
secrets manager by name|http|https://secrets.tailnet.example/api/status
secrets manager by address|http|https://198.51.100.67/api/status
Home Assistant by name|http|http://homeserver:8123/
Home Assistant by address|http|http://198.51.100.19:8123/
OpenShell gateway (host name)|http|https://host.openshell.internal:17670/
OpenShell gateway (loopback)|http|https://127.0.0.1:17670/
metadata address|http|http://169.254.169.254/
upstream MCP gateway (workstation)|http|http://198.51.100.25:8790/
Jobs OpenShell gateway (host name)|http|https://host.openshell.internal:17680/
Jobs OpenShell gateway (loopback)|http|https://127.0.0.1:17680/
'
fail=0; open=0; n=0
echo "box-deny-check mode=$MODE kernel=$(uname -r) user=$(id -un 2>/dev/null || id -u) at $(date -u +%FT%TZ)"
while IFS='|' read -r name kind target; do
  [ -n "$name" ] || continue
  n=$((n+1))
  if [ "$kind" = http ]; then r=$(http "$target"); else r=$(banner "${target%:*}" "${target##*:}"); fi
  case "$r" in ANSWERED*) open=$((open+1)); [ "$MODE" = box ] && fail=$((fail+1));; esac
  printf '%-34s %s\n' "$name" "$r"
done <<EOT
$TARGETS
EOT

if [ "$MODE" = box ]; then
  if [ "$fail" -ne 0 ]; then echo "FAIL: $fail target(s) answered from inside the box"; exit 1; fi
  if [ -z "$CONTROL" ]; then
    echo "NO CONTROL: $n of $n targets refused, but no allowed host was tested, so this is not a pass"; exit 3
  fi
  c=$(http "$CONTROL"); printf '%-34s %s\n' "CONTROL allowed host" "$c"
  case "$c" in
    ANSWERED*) echo "PASS: $n of $n targets refused, and the allowed host answered"; exit 0;;
    *) echo "FAIL: the control did not answer, so the refusals above prove nothing"; exit 1;;
  esac
else
  i=$(http https://secrets.tailnet.example/api/status); h=$(http http://homeserver:8123/)
  printf '%-34s %s\n' "CONTROL secrets manager from host" "$i"
  printf '%-34s %s\n' "CONTROL Home Assistant from host" "$h"
  case "$i|$h" in
    ANSWERED*"|"ANSWERED*) echo "PASS: the checker sees open doors from the host ($open of $n targets answer here)"; exit 0;;
  esac
  echo "FAIL: a host control did not answer; the checker may be blind"; exit 1
fi
