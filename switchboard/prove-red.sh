#!/usr/bin/env bash
# Prove every guard is load-bearing: in a scratch copy of the crate, flip one RED_* constant in
# src/guards.rs to `true` (that guard then lets everything through) and require `cargo test` to fail.
# Output: one `guard=<name> disabled=FAIL-AS-EXPECTED` line per guard, then `RED-OK guards=K/K`.
# A guard whose removal leaves the suite green prints `RED-BROKEN guard=<name>` and the script exits 1.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
WORK="$(mktemp -d /tmp/switchboard-prove-red-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
cp -r "$HERE/Cargo.toml" "$HERE/src" "$WORK/"
[ -f "$HERE/Cargo.lock" ] && cp "$HERE/Cargo.lock" "$WORK/"
export CARGO_TARGET_DIR="$HERE/target/prove-red"
cd "$WORK" || exit 1
if ! "$CARGO" test -q >"$WORK/baseline.log" 2>&1; then
  echo "RED-BROKEN baseline: the unmutated suite does not pass"; tail -5 "$WORK/baseline.log"; exit 1
fi
mapfile -t GUARDS < <(grep -oE '^const RED_[A-Z]+: bool = false;' src/guards.rs | sed -E 's/^const (RED_[A-Z]+).*/\1/')
[ "${#GUARDS[@]}" -gt 0 ] || { echo "RED-BROKEN no RED_* guards found"; exit 1; }
ok=0; broken=0
for g in "${GUARDS[@]}"; do
  cp src/guards.rs "$WORK/guards.orig"
  sed -i -E "s/^const $g: bool = false;/const $g: bool = true;/" src/guards.rs
  "$CARGO" test -q >"$WORK/$g.log" 2>&1
  # Only an assertion failure counts. A compile error (no "test result" line) is a broken proof.
  failing=$(grep -oE '^test result: FAILED\. [0-9]+ passed; [0-9]+ failed' "$WORK/$g.log" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+')
  if [ -n "$failing" ] && [ "$failing" -ge 1 ]; then
    first=$(grep -m1 -E -- '--- FAILED$' "$WORK/$g.log" | sed -E 's/ --- FAILED$//')
    echo "guard=$g disabled=FAIL-AS-EXPECTED failing_tests=$failing first=$first"; ok=$((ok+1))
  elif grep -q '^test result: ok' "$WORK/$g.log"; then
    echo "RED-BROKEN guard=$g disabled=SUITE-STILL-GREEN"; broken=$((broken+1))
  else
    echo "RED-BROKEN guard=$g did-not-compile-or-run"; tail -3 "$WORK/$g.log"; broken=$((broken+1))
  fi
  cp "$WORK/guards.orig" src/guards.rs
done
if [ "$broken" -eq 0 ]; then echo "RED-OK guards=$ok/${#GUARDS[@]}"; exit 0; fi
echo "RED-FAIL broken=$broken/${#GUARDS[@]}"; exit 1
