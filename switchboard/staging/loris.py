#!/usr/bin/env python3
"""FWD-1 regression (slow-body hardening), plus a forged huge Content-Length and fd exhaustion: 16 sockets with no token send a request line and a partial body, then
go quiet. A valid call must still answer within 5 s. Runs the staging build on 127.0.0.1:28800 in a temp dir.
Prints LORIS ok|FAIL and exits 0 only on ok."""
import hashlib, json, os, signal, socket, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "target/staging/debug/switchboard"
TOK = "sbt_loris_test_token"
work = Path(tempfile.mkdtemp(prefix="sb-loris-"))
gen = json.loads((HERE / "generated/agents.json").read_text())
cfg = {"listen": "127.0.0.1:28800", "allowed_sources": ["127.0.0.1"], "prometheus": "http://fake", "audit_log": str(work / "audit.jsonl"),
       "agents": {"coder": {"token_sha256": hashlib.sha256(TOK.encode()).hexdigest(), "tools": ["host_health"], "rate_per_min": 60},
                  "second-agent": {"token_sha256": hashlib.sha256(b"sbt_loris_second").hexdigest(), "tools": ["host_health"], "rate_per_min": 60}},
       "tools": {"host_health": gen["tools"]["host_health"]}}
(work / "config.json").write_text(json.dumps(cfg))
srv = subprocess.Popen([BIN, "serve", "--config", work / "config.json"], stderr=subprocess.DEVNULL, start_new_session=True)
try:
    time.sleep(1)
    socks = []
    for _ in range(16):
        s = socket.create_connection(("127.0.0.1", 28800))
        s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n{")
        socks.append(s)
    time.sleep(1)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "host_health", "arguments": {"host": "workstation"}}}).encode()
    req = urllib.request.Request("http://127.0.0.1:28800/mcp", data=body, headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json"})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=8) as f:
            took, ok = round(time.time() - t, 2), f.status == 200 and time.time() - t < 5
    except Exception as e:  # noqa: BLE001
        took, ok = f"timeout ({e})", False
    print(f"LORIS {'ok' if ok else 'FAIL'}: a valid call with 16 token-less slow bodies open answered in {took} s")
    for s in socks:
        s.close()
    # 2. a token holder (second-agent) opens 16 slow bodies: it may hold at most 4 workers, so coder still answers
    socks = []
    for _ in range(16):
        s = socket.create_connection(("127.0.0.1", 28800))
        s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer sbt_loris_second\r\nContent-Length: 65536\r\n\r\n{")
        socks.append(s)
    time.sleep(1)
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=8) as f:
            took2, ok2 = round(time.time() - t, 2), f.status == 200 and time.time() - t < 5
    except Exception as e:  # noqa: BLE001
        took2, ok2 = f"timeout ({e})", False
    print(f"LORIS {'ok' if ok2 else 'FAIL'}: with another agent's 16 slow bodies open, coder answered in {took2} s")
    ok = ok and ok2
    # 3. keep-alive: a connection reused after 7 s idle still works (a 5 s read timeout broke this once)
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", 28800)
    hdr = {"Authorization": "Bearer " + TOK, "Content-Type": "application/json"}
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    c.request("POST", "/mcp", ping, hdr)
    c.getresponse().read()
    time.sleep(7)
    try:
        c.request("POST", "/mcp", ping, hdr)
        ok3 = c.getresponse().status == 200
    except Exception:  # noqa: BLE001
        ok3 = False
    print(f"LORIS {'ok' if ok3 else 'FAIL'}: a keep-alive connection reused after 7 s idle {'works' if ok3 else 'was dropped'}")
    ok = ok and ok3
    for s in socks:
        s.close()
    # 4. a token-less request declaring an absurd body (tiny_http's drop-time drain would allocate all of it)
    s = socket.create_connection(("127.0.0.1", 28800))
    s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000000000000\r\n\r\n")
    time.sleep(1)
    try:
        with urllib.request.urlopen(req, timeout=8) as f:
            ok4 = srv.poll() is None and f.status == 200
    except Exception:  # noqa: BLE001
        ok4 = False
    print(f"LORIS {'ok' if ok4 else 'FAIL'}: a forged 1 PB Content-Length {'left the server answering' if ok4 else 'took the server down'}")
    ok = ok and ok4
    s.close()
finally:
    os.killpg(srv.pid, signal.SIGTERM)
    srv.wait(timeout=10)

# 5. file descriptors run out (idle connections under a low RLIMIT_NOFILE): tiny_http's accept loop dies on the
# first accept error, which used to leave a live but deaf process. It must exit (systemd restarts it) or still answer.
import resource  # noqa: E402
srv = subprocess.Popen([BIN, "serve", "--config", work / "config.json"], stderr=subprocess.DEVNULL, start_new_session=True,
                       preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (48, 48)))
try:
    time.sleep(1)
    socks = []
    for _ in range(64):
        try:
            socks.append(socket.create_connection(("127.0.0.1", 28800), timeout=2))
        except OSError:
            break
    time.sleep(2)
    for s in socks:
        s.close()
    time.sleep(1)
    try:
        with urllib.request.urlopen(req, timeout=5) as f:
            answered = f.status == 200
    except Exception:  # noqa: BLE001
        answered = False
    try:
        srv.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    ok5 = answered or srv.poll() is not None
    state = "still answers" if answered else (f"exited rc={srv.returncode}" if srv.poll() is not None else "alive but deaf")
    print(f"LORIS {'ok' if ok5 else 'FAIL'}: after fd exhaustion the server {state}")
    ok = ok and ok5
finally:
    if srv.poll() is None:
        os.killpg(srv.pid, signal.SIGTERM)
sys.exit(0 if ok else 1)
