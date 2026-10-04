#!/usr/bin/env bash
# B2: build coder-box:<tag> on workstation and export it as a rootfs tar with a checksum.
# Default: build and export locally only (agent-host is not touched).
# --yes-write: also copy the tar to agent-host:/var/lib/openshell/images/ and verify the checksum there.
# No secrets, no repos and no login go into the image.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
WRITE=0; [[ "${1:-}" == "--yes-write" ]] && WRITE=1
TAG="${TAG:-0.1}"
TAR="$OUT/coder-box_${TAG}.tar"

# The box user's ids must equal the openshell user's on agent-host.
ids="$(hsh 'id -u openshell 2>/dev/null; id -g openshell 2>/dev/null; true' | tr '\n' ' ')"
read -r U G <<<"${ids:-}" || true
if [[ -z "${U:-}" || -z "${G:-}" ]]; then
  U=999; G=988
  echo "NOTE  no openshell user on agent-host yet; building with the expected ids $U/$G (create-box.sh re-checks)"
fi

docker build --progress=plain -t "coder-box:${TAG}" --build-arg SANDBOX_UID="$U" --build-arg SANDBOX_GID="$G" -f "$HERE/image/Dockerfile" "$HERE" > "$OUT/build-${TAG}.log" 2>&1 \
  || { echo "FAIL: docker build (last lines of $OUT/build-${TAG}.log):"; tail -25 "$OUT/build-${TAG}.log"; exit 1; }
echo "built coder-box:${TAG} ($(docker image inspect "coder-box:${TAG}" --format '{{.Size}}' | numfmt --to=iec)) for ids $U/$G"
docker run --rm "coder-box:${TAG}" bash -c '. /opt/coder/profile.sh; echo "claude $(claude --version)"; echo "node $(node -v)  bun $(bun -v)  $(uv --version)"; python3 -V; git --version; gh --version | head -1; ffmpeg -version | head -1 | cut -c1-40; /opt/tts-venv/bin/edge-tts --version; id sandbox; cat /opt/coder-ids'
# Nothing that looks like a login or a token may be in the image.
leak="$(docker run --rm "coder-box:${TAG}" bash -c 'ls -A /home/coder/.claude /home/coder/.claude.json /root/.claude /root/.claude.json 2>/dev/null; grep -rIl -E "sk-ant-|ghp_|github_pat_" /home /root /opt/coder 2>/dev/null' || true)"
[[ -z "$leak" ]] || { echo "FAIL: login or token-shaped files in the image:"; echo "$leak"; exit 1; }
echo "OK    no login and no token-shaped strings in the image"

cid="$(docker create "coder-box:${TAG}")"
docker export "$cid" -o "$TAR"; docker rm "$cid" >/dev/null
SHA="$(sha256sum "$TAR" | cut -d' ' -f1)"
echo "$SHA  coder-box_${TAG}.tar" > "$TAR.sha256"
echo "exported $TAR ($(stat -c %s "$TAR" | numfmt --to=iec)) sha256 $SHA"

if ((WRITE)); then
  scp -q "${SSH_OPTS[@]}" "$TAR" "$AGENT_HOST:/tmp/coder-box_${TAG}.tar"
  hsh "set -e; f=/tmp/coder-box_${TAG}.tar; echo '$SHA  '\$f | sha256sum -c - >/dev/null
       sudo install -o openshell -g openshell -m 640 \$f /var/lib/openshell/images/coder-box_${TAG}.tar; rm -f \$f
       sudo -u openshell sh -c 'cd /var/lib/openshell/images && { grep -v \" coder-box_${TAG}.tar\$\" SHA256SUMS 2>/dev/null; echo \"$SHA  coder-box_${TAG}.tar\"; } > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS && sha256sum -c SHA256SUMS'"
  echo "copied to agent-host:/var/lib/openshell/images/coder-box_${TAG}.tar"
  # Shipped and verified: drop the local copies. This script rebuilds them.
  docker rmi -f "coder-box:${TAG}" >/dev/null && rm -f "$TAR" "$TAR.sha256" && echo "removed local image + tar"
else
  echo "WOULD copy $TAR to agent-host:/var/lib/openshell/images/ and verify sha256 there (--yes-write)"
fi
