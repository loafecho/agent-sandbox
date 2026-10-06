#!/usr/bin/env bash
# Read-only: does the live box `coder` on agent-host match this repo? Exit 0 only if every check passes.
#   drift-check.sh             check: policy, providers, profiles, Infisical secret names, pending rules
#   drift-check.sh --capture   re-write openshell/policy.yaml from the live box (after an approved door), then commit
# Never prints a secret value: the Infisical check reads key names in memory and prints names only.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/bin/lib.sh"
BOX="${BOX:-coder}"
TSV="$HERE/openshell/providers.tsv"
POLICY="${POLICY:-$HERE/openshell/policy.yaml}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAILS=0

osh policy get "$BOX" --full > "$T/live.txt" 2>&1 || { bad "policy get $BOX failed"; cat "$T/live.txt"; exit 1; }

if [ "${1:-}" = "--capture" ]; then
  python3 - "$T/live.txt" "$POLICY" <<'PY'
import sys, yaml
live = yaml.safe_load(open(sys.argv[1]).read().split("\n---\n", 1)[1])
live["network_policies"] = {k: v for k, v in live["network_policies"].items() if not k.startswith("_provider_")}
hdr = "".join(l for l in open(sys.argv[2]) if l.startswith("#") and not l.startswith("# Captured"))
ver = open(sys.argv[1]).readline().split()[-1]
open(sys.argv[2], "w").write(hdr + f"# Captured from live policy v{ver}.\n" + yaml.safe_dump(live, sort_keys=False))
print("captured live policy v" + ver + " into openshell/policy.yaml; review the diff, commit, log the door")
PY
  exit $?
fi

# 1. Named network rules: live == committed (gateway-built _provider_* blocks ignored)
python3 - "$T/live.txt" "$POLICY" > "$T/pol.txt" <<'PY'
import sys, yaml
live = yaml.safe_load(open(sys.argv[1]).read().split("\n---\n", 1)[1])
repo = yaml.safe_load(open(sys.argv[2]))
strip = lambda p: {k: v for k, v in (p.get("network_policies") or {}).items() if not k.startswith("_provider_")}
L, R = strip(live), strip(repo)
for k in sorted(set(L) - set(R)): print(f"live only: {k}")
for k in sorted(set(R) - set(L)): print(f"repo only: {k}")
for k in sorted(set(L) & set(R)):
    if L[k] != R[k]: print(f"differs: {k}")
PY
if [ -s "$T/pol.txt" ]; then bad "policy: live box and openshell/policy.yaml differ"; sed 's/^/      /' "$T/pol.txt"
else ok "policy: live rules == openshell/policy.yaml ($(head -1 "$T/live.txt" | xargs))"; fi

# 2. Providers on the gateway and on the box == providers.tsv
want_all=$(grep -v '^#' "$TSV" | cut -f1 | sort | xargs)
want_box=$(grep -v '^#' "$TSV" | awk -F'\t' -v b="$BOX" '$5==b{print $1}' | sort | xargs)
have_all=$(osh provider list 2>/dev/null | awk 'NR>1{print $1}' | sort | xargs)
have_box=$(osh sandbox provider list "$BOX" 2>/dev/null | awk 'NR>1{print $1}' | sort | xargs)
[ "$have_all" = "$want_all" ] && ok "providers on gateway: $have_all" || bad "providers on gateway: have [$have_all] want [$want_all]"
[ "$have_box" = "$want_box" ] && ok "providers attached to $BOX: $have_box" || bad "providers attached to $BOX: have [$have_box] want [$want_box]"

# 3. Every committed profile is imported and its rules match
for f in "$HERE"/openshell/profile-*.yaml; do
  [ -e "$f" ] || continue
  id=$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["id"])' "$f")
  if ! osh profile export "$id" > "$T/prof.txt" 2>&1; then bad "profile $id: not imported"; continue; fi
  if python3 - "$f" "$T/prof.txt" <<'PY'
import sys, yaml
a = yaml.safe_load(open(sys.argv[1]))
try: b = yaml.safe_load(open(sys.argv[2]))
except Exception: sys.exit(1)
b = b[0] if isinstance(b, list) else b
if isinstance(b, dict) and "profiles" in b: b = b["profiles"][0]
sys.exit(0 if all(b.get(k) == a[k] for k in ("endpoints", "binaries")) else 1)
PY
  then ok "profile $id: imported, endpoints and binaries match"; else bad "profile $id: imported copy differs from $(basename "$f")"; fi
done

# 4. Each provider's secret NAME exists in the Infisical project (values never printed)
PID=$(sed -n 's/^# infisical_project: *//p' "$TSV")
if [ -z "$PID" ] || [ "${PID#TBD}" != "$PID" ]; then bad "infisical: project id not set in providers.tsv"
else
  names=$(infisical secrets --projectId "$PID" --env prod -o json --silent 2>/dev/null |
    python3 -c 'import sys,json; print(" ".join(sorted(s.get("secretKey") or s.get("key","") for s in json.load(sys.stdin))))' 2>/dev/null)
  [ -n "$names" ] || bad "infisical: could not list project $PID (logged in? run: infisical login)"
  for s in $(grep -v '^#' "$TSV" | cut -f4); do
    case " $names " in *" $s "*) ok "infisical: $s present";; *) [ -n "$names" ] && bad "infisical: $s missing in project $PID";; esac
  done
fi

# 5. No pending rules. Approve or reject each by its Chunk id (not the Candidate id): rule reject coder --chunk-id <Chunk>. Never approve-all.
pend=$(osh rule get "$BOX" --status pending 2>/dev/null | grep -c 'Status: pending')
[ "$pend" = 0 ] && ok "pending rules: 0" || { bad "pending rules: $pend"; osh rule get "$BOX" --status pending 2>/dev/null | grep -E 'Chunk:|Rule:|Endpoints|Binaries' | sed 's/^/      /'; }

echo; [ "$FAILS" = 0 ] && { echo "DRIFT-CHECK: CLEAN"; exit 0; } || { echo "DRIFT-CHECK: $FAILS FAIL"; exit 1; }
