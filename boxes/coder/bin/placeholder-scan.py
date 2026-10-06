#!/usr/bin/env python3
"""Find text that would kill a Claude chat inside an OpenShell box.

Once any provider is attached to a box, OpenShell 0.1.1 scans every L7 REST request body,
including Claude's own calls to api.anthropic.com (which re-send the whole chat each turn).
A reserved placeholder in that body is refused with a 403 and the chat is dead from then on.
Grammar copied from OpenShell v0.1.1 crates/openshell-core/src/secrets_body.rs:
  - prefix P followed by zero key chars [A-Za-z0-9_]  -> refused (invalid_token)
  - P + the key name of an attached provider (bare)   -> refused (known_unavailable)
  - P + any other key name                            -> passes today (RISK if a provider with that key is attached later)
  - alias marker A anywhere                           -> RISK (boundary rules are fiddly; treat as unsafe)
  - percent-encoded P counts the same
The text reaches the proxy JSON-encoded, so a newline or quote right after P is also "zero key chars".

The prefixes are built from parts so this file never contains them itself.
Usage: placeholder-scan.py [--known-keys K1,K2] PATH...   (exit 1 if anything would be refused)
"""
import argparse, os, re, sys

P = "openshell" + ":resolve:env" + ":"
P_PCT = "openshell" + "%3Aresolve%3Aenv%3A"
A = "OPENSHELL" + "-RESOLVE-ENV" + "-"
KEY = re.compile(r"[A-Za-z0-9_]*")
DEFAULT_KNOWN = "GITHUB_TOKEN,GH_TOKEN,CLOUDFLARE_API_TOKEN"  # credential keys of the providers in openshell/providers.tsv; pass --known-keys to override


def scan_text(text, known):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pref in (P, P_PCT):
            for m in re.finditer(re.escape(pref), line, flags=re.I if pref is P_PCT else 0):
                key = KEY.match(line, m.end()).group(0)
                if not key:
                    hits.append((lineno, "KILLS", "prefix with no key name after it"))
                elif key in known or re.sub(r"^(v\d+|s[A-Za-z0-9]+)_", "", key) in known:
                    hits.append((lineno, "KILLS", f"names an attached provider key ({key})"))
                else:
                    hits.append((lineno, "risk", f"unknown key '{key}' passes today"))
        if A in line:
            hits.append((lineno, "risk", "alias marker"))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--known-keys", default=DEFAULT_KNOWN)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    known = set(k for k in a.known_keys.split(",") if k)
    kills = files = 0
    for root in a.paths:
        walk = [(root, [], [os.path.basename(root)])] if os.path.isfile(root) else os.walk(root)
        for d, dirs, fs in walk:
            dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
            for f in fs:
                p = root if os.path.isfile(root) else os.path.join(d, f)
                try:
                    with open(p, encoding="utf-8", errors="ignore") as fh:
                        t = fh.read()
                except OSError:
                    continue
                files += 1
                for ln, sev, why in scan_text(t, known):
                    kills += sev == "KILLS"
                    print(f"{sev:5} {p}:{ln}  {why}")
    print(f"scanned {files} files, {kills} would kill a chat", file=sys.stderr)
    sys.exit(1 if kills else 0)


if __name__ == "__main__":
    main()
