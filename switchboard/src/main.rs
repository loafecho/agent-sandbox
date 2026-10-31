//! switchboard: the one MCP tool server every OpenShell box reaches through its own provider.
//! Tools and who may call them
//! come from switchboard/tools.yaml via gen.py; this binary never holds a token value.
//!
//!   switchboard serve --config /etc/switchboard/config.json
//!   switchboard audit-verify [--log /var/lib/switchboard/audit.jsonl]
//!   switchboard check-config --config FILE
//!   switchboard enroll-code [--config FILE]     root only: a one-time code to enroll a passkey (15 min)
//!   switchboard credentials [--config FILE]     how many passkeys are enrolled
//!   switchboard version                         version and build (production | staging)
//!
//! Two listeners: the MCP port (config listen, 16 worker threads) and the passkey page (web.listen,
//! 127.0.0.1 only, 2 threads), each its own pool so a slow forwarded call never blocks the page.

#![cfg_attr(feature = "staging", allow(dead_code))]

mod approve;
mod audit;
mod config;
mod forward;
mod guards;
mod mcp;
mod ntfy;
#[cfg(feature = "staging")]
mod staging;
mod tools;
mod web;
mod webauthn;

use std::io::Read;
use std::sync::Arc;

pub const BUILD: &str = if cfg!(feature = "staging") { "staging" } else { "production" };
const MCP_THREADS: usize = 16;
const WEB_THREADS: usize = 2;
const REAPERS: usize = 4;
/// Extra one-off threads that may drop refused requests when the reaper queue is full.
const MAX_OVERFLOW_DROPS: usize = 256;
static OVERFLOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// A refused request that declares a body bigger than this is never dropped (see `leak`).
const DRAIN_MAX: usize = 1 << 20;
/// Requests abandoned by `leak`; at this many the process exits so systemd restarts it with clean sockets.
const MAX_LEAKS: usize = 256;
static LEAKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// NO socket timeouts: SO_RCVTIMEO on the listener also times out accept(), and tiny_http's accept loop
/// stops for good on the first accept error (lib.rs: `break`), so the server went deaf after 300 idle
/// seconds (found 2026-10-21). Slow bodies are handled by never dropping a refused request on a worker;
/// a dead accept loop (fd exhaustion) exits the process (`accept_died`, `exit_on_server_panic`).
fn listen(addr: &str) -> Result<tiny_http::Server, String> {
    tiny_http::Server::http(addr).map_err(|e| e.to_string())
}

/// Hand a refused request off a worker: to a reaper, or when they are all busy, to a one-off thread.
fn refuse(reap: &std::sync::mpsc::SyncSender<(tiny_http::Request, u16)>, req: tiny_http::Request, status: u16) {
    use std::sync::atomic::Ordering;
    if req.body_length().map_or(false, |n| n > DRAIN_MAX) {
        return leak(req);
    }
    match reap.try_send((req, status)) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full((req, st)) | std::sync::mpsc::TrySendError::Disconnected((req, st))) => {
            if OVERFLOW.fetch_add(1, Ordering::SeqCst) < MAX_OVERFLOW_DROPS {
                std::thread::spawn(move || {
                    let _ = req.respond(tiny_http::Response::from_string(String::new()).with_status_code(st));
                    OVERFLOW.fetch_sub(1, Ordering::SeqCst);
                });
            } else {
                OVERFLOW.fetch_sub(1, Ordering::SeqCst);
                // Past every bound: leak the socket rather than block a worker on its body.
                leak(req);
            }
        }
    }
}

/// Abandon a request without dropping it. tiny_http's EqualReader::drop allocates `vec![0; remaining]` for the
/// whole declared Content-Length before it reads a byte, so dropping a request that declares a huge body aborts
/// the process. A leaked request holds its socket, so leaks are bounded: at MAX_LEAKS the process exits and
/// systemd (Restart=always) starts it again with clean sockets.
fn leak(req: tiny_http::Request) {
    std::mem::forget(req);
    if LEAKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 >= MAX_LEAKS {
        eprintln!("switchboard: {MAX_LEAKS} abandoned connections; exiting so systemd restarts it");
        std::process::exit(1);
    }
}

/// tiny_http's accept loop stops for good on its first accept error (EMFILE, ECONNABORTED, ...) and hands that
/// error to `recv()`; nothing else makes `recv()` fail here. The listener is deaf from then on, so exit and let
/// systemd (Restart=always) bring it back instead of idling forever.
fn accept_died(e: &std::io::Error) -> ! {
    eprintln!("switchboard: accept loop stopped ({e}); exiting so systemd restarts it");
    std::process::exit(1)
}

/// A panic inside tiny_http (its accept thread unwraps `try_clone()`, which fails on EMFILE) leaves `recv()`
/// blocked forever with no error. Exit instead, so systemd restarts the process.
fn exit_on_server_panic() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        if info.location().map_or(false, |l| l.file().contains("tiny_http")) {
            eprintln!("switchboard: the HTTP server thread panicked; exiting so systemd restarts it");
            std::process::exit(1);
        }
    }));
}

/// Requests refused before their body was read. tiny_http drains the rest of the body when a request is
/// dropped (EqualReader::drop), so the reply and the drop happen here, never on an MCP worker.
fn reaper() -> std::sync::mpsc::SyncSender<(tiny_http::Request, u16)> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<(tiny_http::Request, u16)>(256);
    let rx = Arc::new(std::sync::Mutex::new(rx));
    for _ in 0..REAPERS {
        let rx = rx.clone();
        std::thread::spawn(move || loop {
            let next = rx.lock().unwrap().recv();
            match next {
                Ok((req, status)) => {
                    let _ = req.respond(tiny_http::Response::from_string(String::new()).with_status_code(status));
                }
                Err(_) => return,
            }
        });
    }
    tx
}

fn arg(args: &[String], flag: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let code = match cmd {
        "serve" => serve(&arg(&args, "--config", "/etc/switchboard/config.json")),
        "audit-verify" => match audit::verify(&arg(&args, "--log", "/var/lib/switchboard/audit.jsonl")) {
            Ok((n, last)) => {
                println!("AUDIT-VERIFY: chain OK entries={n} last={}", &last[..12.min(last.len())]);
                0
            }
            Err(e) => {
                println!("AUDIT-VERIFY: BROKEN {e}");
                1
            }
        },
        "check-config" => match config::Config::load(&arg(&args, "--config", "/etc/switchboard/config.json")) {
            Ok(c) => {
                println!("CONFIG OK agents={} tools={}", c.agents.len(), c.tools.len());
                0
            }
            Err(e) => {
                println!("CONFIG BAD {e}");
                1
            }
        },
        "version" => {
            println!("switchboard {} build={BUILD}", env!("CARGO_PKG_VERSION"));
            0
        }
        "enroll-code" => enroll_code(&arg(&args, "--config", "/etc/switchboard/config.json")),
        "credentials" => match config::Config::load(&arg(&args, "--config", "/etc/switchboard/config.json")) {
            Ok(c) => match &c.web {
                Some(w) => {
                    println!("CREDENTIALS enrolled={}", webauthn::Credentials::open(&w.credentials_file).count());
                    0
                }
                None => {
                    println!("CREDENTIALS web page is off");
                    1
                }
            },
            Err(e) => {
                println!("CONFIG BAD {e}");
                1
            }
        },
        _ => {
            eprintln!("usage: switchboard serve|audit-verify|check-config|enroll-code|credentials|version [--config FILE] [--log FILE]");
            2
        }
    };
    std::process::exit(code);
}

fn euid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

/// A one-time enrollment code. Production builds run this only as root: the switchboard service
/// user can never mint one, so nothing reachable from the network can enroll a passkey.
fn enroll_code(path: &str) -> i32 {
    if !config::STAGING && euid() != Some(0) {
        eprintln!("enroll-code: run as root (sudo / qm guest exec)");
        return 1;
    }
    let cfg = match config::Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 1;
        }
    };
    let Some(w) = &cfg.web else {
        eprintln!("enroll-code: the web page is off in this config");
        return 1;
    };
    // Production: root's file in /etc/switchboard, group switchboard read-only, set on the open file.
    let group = if config::STAGING { None } else { group_id("switchboard") };
    if !config::STAGING && group.is_none() {
        eprintln!("enroll-code: no switchboard group");
        return 1;
    }
    match webauthn::new_enroll_code_for(&w.enroll_file, approve::now_secs(), group) {
        Ok(code) => {
            println!("ENROLL CODE {code} (one passkey, valid 15 minutes): open {}/enroll on the phone", w.origin);
            0
        }
        Err(e) => {
            eprintln!("enroll-code: {e}");
            1
        }
    }
}

fn group_id(name: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find(|l| l.split(':').next() == Some(name))?
        .split(':')
        .nth(2)?
        .parse()
        .ok()
}

/// Keys arrive as a systemd credential (LoadCredential=secrets.env), not as the unit's environment, so
/// they never sit in /proc/<pid>/environ (SEC-3, round 2). Loaded into the process's own environment
/// map (which /proc does not show) for the code below, and each is removed once read.
fn load_credentials() {
    let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") else { return };
    let Ok(text) = std::fs::read_to_string(std::path::Path::new(&dir).join("secrets.env")) else {
        return;
    };
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
                std::env::set_var(k, v);
            }
        }
    }
}

/// Forwarded-tool backends, each with its own key from the environment (removed once read).
fn upstreams(cfg: &config::Config) -> Result<std::collections::BTreeMap<String, Box<dyn forward::Upstream>>, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut keys: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for b in cfg.backends.values() {
        if !keys.contains_key(&b.token_env) {
            let v = std::env::var(&b.token_env).map_err(|_| format!("{} is not set", b.token_env))?;
            if v.trim().is_empty() {
                return Err(format!("{} is empty", b.token_env));
            }
            keys.insert(b.token_env.clone(), v.trim().to_string());
        }
    }
    for k in keys.keys() {
        std::env::remove_var(k);
    }
    for (name, b) in &cfg.backends {
        out.insert(
            name.clone(),
            Box::new(forward::HttpUpstream::new(&b.url, &keys[&b.token_env])) as Box<dyn forward::Upstream>,
        );
    }
    Ok(out)
}

/// Keys come from the environment, loaded from the systemd credential secrets.env (load_credentials; source /etc/switchboard/secrets.env, root 0600)
/// and are removed from it once read. A configured backend with a missing key refuses to start.
fn backends(cfg: &config::Config) -> Result<tools::Backends, String> {
    fn take(name: &str) -> Result<String, String> {
        let v = std::env::var(name).map_err(|_| format!("{name} is not set"))?;
        std::env::remove_var(name);
        if v.trim().is_empty() {
            return Err(format!("{name} is empty"));
        }
        Ok(v.trim().to_string())
    }
    let pve: Option<Box<dyn tools::JsonGet>> = match &cfg.pve {
        Some(p) => Some(Box::new(tools::HttpJson::pve(
            &p.base,
            &p.ca_file,
            &take("PVE_TOKEN_ID")?,
            &take("PVE_TOKEN_SECRET")?,
        )?)),
        None => None,
    };
    let jf_key = match &cfg.jellyfin {
        Some(_) => take("JELLYFIN_API_KEY")?,
        None => String::new(),
    };
    let jellyfin: Option<Box<dyn tools::JsonGet>> = cfg
        .jellyfin
        .as_ref()
        .map(|base| Box::new(tools::HttpJson::jellyfin(base, &jf_key)) as Box<dyn tools::JsonGet>);
    // Write types exist only when an approve-tier tool needs them.
    let pve_power: Option<Box<dyn tools::PveWrite>> = match (&cfg.pve, cfg.tools.contains_key("pve_guest_power")) {
        (Some(p), true) => Some(Box::new(tools::HttpPvePower::new(
            &p.base,
            &p.ca_file,
            &take("PVE_POWER_TOKEN_ID")?,
            &take("PVE_POWER_TOKEN_SECRET")?,
        )?)),
        _ => None,
    };
    let jf_write: Option<Box<dyn tools::JfWrite>> = match (&cfg.jellyfin, cfg.tools.contains_key("jellyfin_library_scan")) {
        (Some(base), true) => Some(Box::new(tools::HttpJfWrite::new(base, &jf_key))),
        _ => None,
    };
    drop(jf_key);
    Ok(tools::Backends {
        prom: Box::new(tools::HttpProm::new(&cfg.prometheus)),
        pve,
        pve_node: cfg.pve.as_ref().map(|p| p.node.clone()).unwrap_or_default(),
        jellyfin,
        pve_power,
        jf_write,
    })
}

fn serve(path: &str) -> i32 {
    exit_on_server_panic();
    load_credentials();
    let cfg = match config::Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 1;
        }
    };
    let audit = match audit::Audit::open(&cfg.audit_log) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let server = match listen(&cfg.listen) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("listen {}: {e}", cfg.listen);
            return 1;
        }
    };
    let web_server = match &cfg.web {
        Some(w) => match listen(&w.listen) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                eprintln!("listen {}: {e}", w.listen);
                return 1;
            }
        },
        None => None,
    };
    #[cfg(not(feature = "staging"))]
    let built = backends(&cfg).and_then(|b| upstreams(&cfg).map(|u| (b, u)));
    #[cfg(feature = "staging")]
    let built = Ok::<_, String>((staging::backends(&cfg), upstreams(&cfg).unwrap_or_default()));
    let (backends, upstreams) = match built {
        Ok(b) => b,
        Err(e) => {
            eprintln!("backends: {e}");
            return 1;
        }
    };
    audit.record(serde_json::json!({"event": "start", "version": env!("CARGO_PKG_VERSION"), "build": BUILD}));
    let approvals = match &cfg.approvals {
        Some(a) => {
            #[cfg(not(feature = "staging"))]
            let (discord, notify): (Box<dyn approve::Discord>, Option<Box<dyn approve::Notify>>) = {
                let token = match std::env::var("DISCORD_BOT_TOKEN") {
                    Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
                    _ => {
                        eprintln!("backends: DISCORD_BOT_TOKEN is not set");
                        return 1;
                    }
                };
                std::env::remove_var("DISCORD_BOT_TOKEN");
                let notify = match &cfg.ntfy {
                    Some(n) => {
                        let t = match std::env::var("NTFY_TOKEN") {
                            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
                            _ => {
                                eprintln!("backends: NTFY_TOKEN is not set");
                                return 1;
                            }
                        };
                        std::env::remove_var("NTFY_TOKEN");
                        match ntfy::HttpNtfy::new(&n.url, &n.topic, &t, n.pin_ip.as_deref()) {
                            Ok(h) => Some(Box::new(h) as Box<dyn approve::Notify>),
                            Err(e) => {
                                eprintln!("backends: {e}");
                                return 1;
                            }
                        }
                    }
                    None => None,
                };
                (Box::new(approve::HttpDiscord::new(&a.channel, &token)), notify)
            };
            #[cfg(feature = "staging")]
            let (discord, notify) = staging::discord_and_notify(&cfg);
            let mut ap = approve::Approvals::open(a.clone(), discord, &audit, approve::now_secs());
            ap.notify = notify;
            ap.page = cfg.web.as_ref().map(|w| w.origin.clone());
            Some(ap)
        }
        None => None,
    };
    // Nothing that held a key value is in the environment any more.
    for k in ["TS_AUTHKEY"] {
        std::env::remove_var(k);
    }
    let web = cfg.web.clone().map(web::Web::new);
    let sb = Arc::new(mcp::Switchboard {
        backends,
        cfg,
        audit,
        rate: guards::RateLimiter::new(),
        approvals,
        upstreams,
        inflight: forward::InFlight::new(),
        web,
    });
    if sb.approvals.is_some() {
        let p = sb.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            p.poll(approve::now_secs());
        });
    }
    let reap = reaper();
    if let Some(ws) = web_server {
        for _ in 0..WEB_THREADS {
            let (ws, sb, reap) = (ws.clone(), sb.clone(), reap.clone());
            std::thread::spawn(move || loop {
                match ws.recv() {
                    Ok(req) => web_one(&sb, req, &reap),
                    Err(e) => accept_died(&e),
                }
            });
        }
        eprintln!("switchboard web page on {}", sb.cfg.web.as_ref().map(|w| w.listen.as_str()).unwrap_or(""));
    }
    eprintln!("switchboard {} ({BUILD}) listening on {}", env!("CARGO_PKG_VERSION"), sb.cfg.listen);
    let workers: Vec<_> = (0..MCP_THREADS)
        .map(|_| {
            let (server, sb, reap) = (server.clone(), sb.clone(), reap.clone());
            std::thread::spawn(move || loop {
                match server.recv() {
                    Ok(req) => mcp_one(&sb, req, &reap),
                    Err(e) => accept_died(&e),
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    0
}

fn header(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
}

/// Every line of a header, joined with ", ". A repeated X-Forwarded-For line then reads as a second address,
/// which guards::web_device refuses, instead of the first line silently winning.
fn header_all(req: &tiny_http::Request, name: &'static str) -> Option<String> {
    let v: Vec<&str> = req.headers().iter().filter(|h| h.field.equiv(name)).map(|h| h.value.as_str()).collect();
    if v.is_empty() {
        None
    } else {
        Some(v.join(", "))
    }
}

fn mcp_one(sb: &mcp::Switchboard, mut req: tiny_http::Request, reap: &std::sync::mpsc::SyncSender<(tiny_http::Request, u16)>) {
    let src = req.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let auth = header(&req, "Authorization");
    let method = req.method().as_str().to_string();
    let path = req.url().to_string();
    // Headers only, before any of the body is read: a caller without a valid token never holds a worker
    // while it trickles a body in, and one agent holds at most AGENT_REQUESTS workers (FWD-1, round 2).
    let agent = match sb.preauth(&src, &method, &path, auth.as_deref(), req.body_length()) {
        Ok(a) => a,
        Err(r) => return refuse(reap, req, r.status),
    };
    let Some(_slot) = sb.inflight.enter(&[(format!("req:{agent}"), mcp::AGENT_REQUESTS)]) else {
        return refuse(reap, req, 429);
    };
    let mut body = Vec::new();
    let _ = req.as_reader().take((mcp::MAX_BODY + 1) as u64).read_to_end(&mut body);
    let reply = sb.handle(&src, &method, &path, auth.as_deref(), &body);
    let resp = match reply.body {
        Some(b) => tiny_http::Response::from_string(b)
            .with_status_code(reply.status)
            .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()),
        None => tiny_http::Response::from_string(String::new()).with_status_code(reply.status),
    };
    let _ = req.respond(resp);
}

fn web_one(sb: &mcp::Switchboard, mut req: tiny_http::Request, reap: &std::sync::mpsc::SyncSender<(tiny_http::Request, u16)>) {
    let origin = header(&req, "Origin");
    let xff = header_all(&req, "X-Forwarded-For");
    let peer = req.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let method = req.method().as_str().to_string();
    let path = req.url().to_string();
    let caller = web::Caller {
        xff: xff.as_deref(),
        peer: &peer,
    };
    // Headers only, before any of the body is read: a caller that is not the phone, or a declared body the page
    // would refuse anyway, never holds one of the two web workers or reaches tiny_http's drain on drop.
    if let Some(status) = web::prebody(sb, &caller, &method, &path, req.body_length()) {
        return refuse(reap, req, status);
    }
    let mut body = Vec::new();
    let _ = req.as_reader().take((web::MAX_WEB_BODY + 1) as u64).read_to_end(&mut body);
    let r = web::handle(sb, &caller, &method, &path, origin.as_deref(), &body, approve::now_secs());
    let h = |s: String| s.parse::<tiny_http::Header>().unwrap();
    let resp = tiny_http::Response::from_string(r.body)
        .with_status_code(r.status)
        .with_header(h(format!("Content-Type: {}", r.ctype)))
        .with_header(h(format!("Content-Security-Policy: {}", web::CSP)))
        .with_header(h("Cache-Control: no-store".into()))
        .with_header(h("X-Content-Type-Options: nosniff".into()))
        .with_header(h("Referrer-Policy: no-referrer".into()))
        .with_header(h("X-Frame-Options: DENY".into()));
    let _ = req.respond(resp);
}
