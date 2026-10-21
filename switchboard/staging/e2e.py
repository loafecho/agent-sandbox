#!/usr/bin/env python3
"""Staging end-to-end for the passkey page, on a dev machine or CI (never on the switchboard VM). Builds the switchboard with
`--features staging` (RP localhost, fake Discord / ntfy / backends that live in files), starts it on
127.0.0.1, enrolls a software passkey through the real `switchboard enroll-code` path, then:

  1. a web approve executes once                      (writes.log 1 line, executed events 1)
  2. a web deny denies                                (status denied, no write)
  3. Discord ✅ plus a web approve on one request      (executed events = 1)
  4. a forged assertion and a replayed one are refused (web_refused events in the audit log)

Every check prints `E2E <name> ... PASS|FAIL`; the last line is `E2E-STAGING pass=N/M`. Exit 0 only if all pass.
The soft authenticator signs exactly as a phone does (ES256, flags UP|UV, signCount 0).
"""
import base64, hashlib, json, os, re, signal, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent.parent
CARGO = os.environ.get("CARGO", str(Path.home() / ".cargo/bin/cargo"))
MCP_PORT, WEB_PORT = 18800, 18801
ORIGIN, RP = f"http://localhost:{WEB_PORT}", "localhost"
TOKEN = "sbt_staging_" + base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
APPROVER = "100000000000000001"
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"E2E {name} ... {'PASS' if ok else 'FAIL'}{('  ' + detail) if detail else ''}", flush=True)


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cbor_bytes(major, b):
    n = len(b)
    head = bytes([(major << 5) | n]) if n < 24 else bytes([(major << 5) | 24, n]) if n < 256 else bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return head + b


class Soft:
    """A software passkey."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(16)
        self.count = 0

    def auth_data(self, flags=0x05, with_cred=False):
        d = hashlib.sha256(RP.encode()).digest() + bytes([flags | (0x40 if with_cred else 0)]) + self.count.to_bytes(4, "big")
        if with_cred:
            n = self.key.public_key().public_numbers()
            cose = (bytes([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]) + cbor_bytes(2, n.x.to_bytes(32, "big"))
                    + bytes([0x22]) + cbor_bytes(2, n.y.to_bytes(32, "big")))
            d += bytes(16) + len(self.id).to_bytes(2, "big") + self.id + cose
        return d

    def client_data(self, ty, challenge, origin=ORIGIN):
        return json.dumps({"type": ty, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def sign(self, ad, cd, key=None):
        return (key or self.key).sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))


def http(method, port, path, body=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=30) as f:
            t = f.read().decode()
            return f.status, (json.loads(t) if t.startswith(("{", "[")) else t)
    except urllib.error.HTTPError as e:
        t = e.read().decode()
        return e.code, (json.loads(t) if t.startswith("{") else t)


def web(path, body):
    return http("POST", WEB_PORT, path, body, {"Origin": ORIGIN})


def mcp(tool, args):
    s, v = http("POST", MCP_PORT, "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}},
                {"Authorization": "Bearer " + TOKEN})
    return json.loads(v["result"]["content"][0]["text"])


def assert_with(soft, rid, decision, key=None, replay=None):
    s, o = web(f"/r/{rid}/options", {"decision": decision})
    if "challenge" not in o:
        return s, o, None
    cd = soft.client_data("webauthn.get", o["challenge"])
    ad = soft.auth_data()
    body = {"decision": decision, "id": b64e(soft.id), "clientDataJSON": b64e(cd), "authenticatorData": b64e(ad), "signature": b64e(soft.sign(ad, cd, key))}
    s, r = web(f"/r/{rid}/assert", replay or body)
    return s, r, body


def main():
    print(">>> build (staging feature)", flush=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(HERE / "target/staging"))
    b = subprocess.run([CARGO, "build", "-q", "--features", "staging"], cwd=HERE, env=env, capture_output=True, text=True)
    if b.returncode:
        print(b.stderr[-2000:])
        return 1
    BIN = HERE / "target/staging/debug/switchboard"
    ver = subprocess.run([BIN, "version"], capture_output=True, text=True).stdout.strip()
    check("binary is the staging build", ver.endswith("build=staging"), ver)
    work = Path(tempfile.mkdtemp(prefix="sb-staging-"))
    gen = json.loads((HERE / "generated/agents.json").read_text())
    tools = {k: gen["tools"][k] for k in ("jellyfin_library_scan", "request_status", "host_health")}
    cfg = {"listen": f"127.0.0.1:{MCP_PORT}", "allowed_sources": ["127.0.0.1"], "prometheus": "http://fake",
           "jellyfin": "http://fake", "audit_log": str(work / "audit.jsonl"),
           "approvals": {"guild": "100000000000000003", "channel": "100000000000000004", "approver": APPROVER,
                         "window_secs": 1800, "max_pending": 3, "state_file": str(work / "requests.json")},
           "web": {"listen": f"127.0.0.1:{WEB_PORT}", "allow_src": ["127.0.0.1"], "rp_id": RP, "origin": ORIGIN,
                   "credentials_file": str(work / "credentials.json"), "enroll_file": str(work / "enroll.json")},
           "ntfy": {"url": "https://ntfy.invalid", "topic": "approvals"},
           "agents": {"coder": {"token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest(), "tools": sorted(tools), "rate_per_min": 60}},
           "tools": tools}
    (work / "config.json").write_text(json.dumps(cfg))
    srv = subprocess.Popen([BIN, "serve", "--config", work / "config.json"], stderr=open(work / "serve.log", "w"), start_new_session=True)
    try:
        for _ in range(100):
            try:
                if http("GET", WEB_PORT, "/enroll")[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        audit = lambda: [json.loads(l) for l in (work / "audit.jsonl").read_text().splitlines()]
        events = lambda rid, ev: sum(1 for e in audit() if e.get("request") == rid and e.get("event") == ev)
        writes = lambda: len((work / "writes.log").read_text().splitlines()) if (work / "writes.log").exists() else 0

        # enrollment: the real one-time code path
        out = subprocess.run([BIN, "enroll-code", "--config", work / "config.json"], capture_output=True, text=True).stdout
        code = re.search(r"ENROLL CODE ([A-Z0-9]{12})", out).group(1)
        soft = Soft()
        s, o = web("/enroll/options", {"code": code})
        cd = soft.client_data("webauthn.create", o["challenge"])
        ad = soft.auth_data(with_cred=True)
        att = bytes([0xA3]) + cbor_bytes(3, b"fmt") + cbor_bytes(3, b"none") + cbor_bytes(3, b"attStmt") + bytes([0xA0]) + cbor_bytes(3, b"authData") + cbor_bytes(2, ad)
        s, r = web("/enroll/finish", {"code": code, "clientDataJSON": b64e(cd), "attestationObject": b64e(att)})
        n = subprocess.run([BIN, "credentials", "--config", work / "config.json"], capture_output=True, text=True).stdout.strip()
        check("soft authenticator enrolled via enroll-code", s == 200 and n == "CREDENTIALS enrolled=1", f"{r} {n}")
        s, r = web("/enroll/options", {"code": code})
        check("the enroll code works once", s == 403, str(r))

        # 1. web approve executes once
        rid = mcp("jellyfin_library_scan", {})["request"]
        push = [json.loads(l) for l in (work / "ntfy.jsonl").read_text().splitlines()]
        check("request pushed to the phone (fake ntfy) with the page link", push[-1]["click"] == f"{ORIGIN}/r/{rid}", f"ntfy id {push[-1]['id']}")
        s, r, _ = assert_with(soft, rid, "approve")
        time.sleep(6)  # a poller pass
        check("web approve executes once", s == 200 and r.get("status") == "executed" and writes() == 1 and events(rid, "executed") == 1,
              f"{rid} status={r.get('status')} writes={writes()} executed_events={events(rid, 'executed')}")
        s, r, _ = assert_with(soft, rid, "approve")
        check("a second approve on it is refused", s == 409, str(r))

        # 2. web deny denies
        rid2 = mcp("jellyfin_library_scan", {})["request"]
        s, r, _ = assert_with(soft, rid2, "deny")
        st = mcp("request_status", {"id": rid2})["status"]
        check("web deny denies", s == 200 and st == "denied" and writes() == 1 and events(rid2, "denied") == 1,
              f"{rid2} status={st} writes={writes()}")

        # 3. Discord ✅ and a web approve on one request
        rid3 = mcp("jellyfin_library_scan", {})["request"]
        msg = next(e for e in audit() if e.get("request") == rid3 and e.get("event") == "requested")["message"]
        s, o = web(f"/r/{rid3}/options", {"decision": "approve"})
        fake = json.loads((work / "fake-discord.json").read_text())
        fake["reactions"].setdefault(f"{msg} ✅", []).append(APPROVER)
        (work / "fake-discord.json").write_text(json.dumps(fake))
        cd = soft.client_data("webauthn.get", o["challenge"])
        ad = soft.auth_data()
        s, r = web(f"/r/{rid3}/assert", {"decision": "approve", "id": b64e(soft.id), "clientDataJSON": b64e(cd), "authenticatorData": b64e(ad), "signature": b64e(soft.sign(ad, cd))})
        time.sleep(11)  # two poller passes see the approver's ✅
        check("Discord ✅ plus a web approve on one request", events(rid3, "executed") == 1 and writes() == 2,
              f"{rid3} executed_events={events(rid3, 'executed')} writes={writes()} web={r.get('status') or r.get('error')}")

        # 4. a forged and a replayed assertion
        rid4 = mcp("jellyfin_library_scan", {})["request"]
        s, r, _ = assert_with(soft, rid4, "approve", key=ec.generate_private_key(ec.SECP256R1()))
        check("forged signature refused", s == 403 and "signature" in r.get("error", "") and events(rid4, "web_refused") == 1, str(r))
        s, r, body = assert_with(soft, rid4, "deny")
        s2, r2, _ = assert_with(soft, rid4, "approve", replay=dict(body, decision="approve"))
        st = mcp("request_status", {"id": rid4})["status"]
        check("replayed deny assertion cannot approve", st == "denied" and s2 in (403, 409), f"replay -> {s2} {r2}, status {st}")
        # 5. only the allowed device: a caller tailscale serve reports as workstation is refused before anything else
        s, r = http("GET", WEB_PORT, f"/r/{rid4}", headers={"X-Forwarded-For": "198.51.100.25"})
        s2, r2 = http("POST", WEB_PORT, f"/r/{rid4}/options", {"decision": "approve"}, {"Origin": ORIGIN, "X-Forwarded-For": "198.51.100.25"})
        check("a caller that is not the phone gets 403", s == 403 and s2 == 403, f"GET {s}, POST {s2}")
        v = subprocess.run([BIN, "audit-verify", "--log", work / "audit.jsonl"], capture_output=True, text=True).stdout.strip()
        check("audit chain", v.startswith("AUDIT-VERIFY: chain OK"), v)
    finally:
        os.killpg(srv.pid, signal.SIGTERM)
        srv.wait(timeout=10)
    print(f"E2E-STAGING pass={sum(RESULTS)}/{len(RESULTS)} (work dir {work})")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
