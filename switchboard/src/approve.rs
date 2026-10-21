//! The approve tier. An approve-tier call never runs: it becomes a request, posted to Discord
//! #approvals with the approver @-mentioned and ✅/❌ added by the bot, and the call returns
//! `pending` at once. A poller (every 5 s, main.rs) reads the reactions:
//!   - the approver's ❌ → denied;  the approver's ✅ → the write runs, then `executed`/`failed`;
//!   - nobody else counts (guards::approver_reacted), the bot's own ✅ included;
//!   - past the window (30 min) → expired.
//! Requests are kept in `state_file`; any still pending when the switchboard starts are expired
//! (a restart never carries an approval over). At most `max_pending` pending per agent.
//! Every step is audited. Once decided, the bot edits the request message to its outcome
//! (ran / cancelled / expired / failed), so #approvals reads as a list of decisions.
//! v0.4: the approver can also decide on the passkey page (web.rs); an ntfy push on topic `approvals` links to
//! it. Whichever decision comes first wins: `claim` is a check-and-set under the lock, so a Discord ✅
//! and a passkey approve on the same request run the write once (guards::claimable, RED_CLAIMONCE).

use crate::audit::Audit;
use crate::config::{ApprovalsCfg, Config};
use crate::guards;
use crate::tools::{self, Backends};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const YES: &str = "✅";
pub const NO: &str = "❌";
const KEEP: usize = 200;

/// The phone push for a new request. Returns the ntfy message id.
pub trait Notify: Send + Sync {
    fn publish(&self, title: &str, message: &str, click: &str) -> Result<String, String>;
}

/// The Discord calls the approve tier needs, and nothing else.
pub trait Discord: Send + Sync {
    /// Post to the approvals channel; returns the message id. Only `mention` may be pinged.
    fn post(&self, content: &str, mention: &str) -> Result<String, String>;
    fn react(&self, msg: &str, emoji: &str) -> Result<(), String>;
    /// User ids that reacted with `emoji` (the bot included, when it reacted).
    fn reactors(&self, msg: &str, emoji: &str) -> Result<Vec<String>, String>;
    /// Replace the bot's own message text with the outcome. Pings nobody.
    fn finish(&self, msg: &str, content: &str) -> Result<(), String>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    pub id: String,
    pub agent: String,
    pub tool: String,
    pub args: Value,
    /// Guest kind for pve_guest_power ("qemu"/"lxc"), resolved before posting.
    #[serde(default)]
    pub kind: String,
    pub message: String,
    /// What was asked, in words ("scan the Jellyfin library").
    #[serde(default)]
    pub summary: String,
    pub created: u64,
    /// sha256 of the canonical args JSON: a passkey challenge is bound to it.
    #[serde(default)]
    pub args_sha256: String,
    pub status: String,
    #[serde(default)]
    pub decided: Option<u64>,
    #[serde(default)]
    pub result: Option<String>,
}

pub struct Approvals {
    pub cfg: ApprovalsCfg,
    pub discord: Box<dyn Discord>,
    pub notify: Option<Box<dyn Notify>>,
    /// The approval page base (https://switchboard.tailnet.example), when the web page is on.
    pub page: Option<String>,
    reqs: Mutex<Vec<Request>>,
    seq: AtomicU64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Approvals {
    /// Load the saved requests and expire every one still pending (a restart never keeps one).
    pub fn open(cfg: ApprovalsCfg, discord: Box<dyn Discord>, audit: &Audit, now: u64) -> Approvals {
        let mut reqs: Vec<Request> = std::fs::read_to_string(&cfg.state_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let mut stale = Vec::new();
        reqs.retain(|r| r.status != "posting"); // never posted: nothing to tell anyone
        for r in reqs.iter_mut().filter(|r| r.status == "pending" || r.status == "approved") {
            // "approved" means a write was claimed but no outcome was recorded: the process died mid-run
            // (RACE-5, round 2). It may or may not have run, so say exactly that.
            let running = r.status == "approved";
            r.status = if running { "failed".into() } else { "expired".into() };
            r.decided = Some(now);
            r.result = Some(if running {
                "switchboard restarted while it was running; it may or may not have run".into()
            } else {
                "switchboard restarted".into()
            });
            audit
                .record(json!({"event": if running { "interrupted" } else { "expired" }, "request": r.id, "agent": r.agent, "tool": r.tool, "why": "restart"}));
            stale.push((r.clone(), running));
        }
        let a = Approvals {
            cfg,
            discord,
            notify: None,
            page: None,
            reqs: Mutex::new(reqs),
            seq: AtomicU64::new(0),
        };
        a.save();
        for (r, running) in stale {
            let text = if running {
                outcome(
                    &r,
                    "⚠️ **Unknown**",
                    "It was approved, but the switchboard restarted while it was running. Check whether it ran.",
                    now,
                )
            } else {
                outcome(&r, "⌛ **Expired**", "The switchboard restarted before you decided. Nothing ran.", now)
            };
            let _ = a.discord.finish(&r.message, &text);
        }
        a
    }

    fn save(&self) {
        let reqs = self.reqs.lock().unwrap();
        let start = reqs.len().saturating_sub(KEEP);
        let body = serde_json::to_string_pretty(&reqs[start..]).unwrap_or_default();
        let tmp = format!("{}.tmp", self.cfg.state_file);
        if std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &self.cfg.state_file)).is_err() {
            eprintln!("approvals: could not save {}", self.cfg.state_file);
        }
    }

    fn new_id(&self, now: u64) -> String {
        let n = self.seq.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let h = hex::encode(Sha256::digest(format!("{now}-{}-{n}-{nanos}", std::process::id()).as_bytes()));
        format!("r-{}", &h[..12])
    }

    fn link(&self, msg: &str) -> String {
        format!("https://discord.com/channels/{}/{}/{}", self.cfg.guild, self.cfg.channel, msg)
    }

    /// Turn an approve-tier call into a pending request. Everything that can refuse it (the power
    /// allowlist, an unknown guest, too many pending) runs before anything is posted.
    pub fn submit(&self, cfg: &Config, b: &Backends, audit: &Audit, agent: &str, tool: &str, args: &Value, now: u64) -> Result<Value, String> {
        let (kind, what) = match tool {
            "pve_guest_power" => {
                let vmid = args["vmid"].as_str().unwrap_or("");
                let action = args["action"].as_str().unwrap_or("");
                guards::power_allowed(&cfg.power_vmids, vmid).map_err(|d| d.why)?;
                let pve = b.pve.as_deref().ok_or("proxmox backend is not configured")?;
                let (kind, name) = tools::pve_guest(pve, vmid)?;
                let verb = match action {
                    "shutdown" => "shut down",
                    "reboot" => "restart",
                    _ => "start",
                };
                (kind.clone(), format!("{verb} {name} (guest {vmid})"))
            }
            "jellyfin_library_scan" => (String::new(), "scan the Jellyfin library".to_string()),
            _ => return Err(format!("{tool} is not an approve-tier tool")),
        };
        // Reserve the slot before the Discord round trip, under one lock (RACE-1, round 2): concurrent calls
        // all see the reservation, so max_pending holds.
        let id = self.new_id(now);
        {
            let mut reqs = self.reqs.lock().unwrap();
            let pending = reqs
                .iter()
                .filter(|r| r.agent == agent && (r.status == "pending" || r.status == "posting"))
                .count();
            if pending >= self.cfg.max_pending {
                return Err(format!("{agent} already has {pending} pending requests (max {})", self.cfg.max_pending));
            }
            reqs.push(Request {
                id: id.clone(),
                agent: agent.into(),
                tool: tool.into(),
                args: args.clone(),
                kind: kind.clone(),
                message: String::new(),
                summary: what.clone(),
                created: now,
                args_sha256: args_sha256(args),
                status: "posting".into(),
                decided: None,
                result: None,
            });
        }
        let expires = now + self.cfg.window_secs;
        let face = if self.page.is_some() { " · or passkey from the phone alert" } else { "" };
        let content = format!(
            "<@{}> **{} wants to {what}.**\n{YES} run it · {NO} cancel{face} · open until <t:{expires}:t>\n-# request {id} · only your tap counts",
            self.cfg.approver,
            title(agent)
        );
        let msg = match self.discord.post(&content, &self.cfg.approver) {
            Ok(m) => m,
            Err(e) => {
                self.reqs.lock().unwrap().retain(|r| r.id != id);
                return Err(format!("could not post the approval request: {e}"));
            }
        };
        let mut reacted = true;
        for e in [YES, NO] {
            reacted &= self.discord.react(&msg, e).is_ok();
        }
        if let Some(r) = self.reqs.lock().unwrap().iter_mut().find(|r| r.id == id) {
            r.message = msg.clone();
            r.status = "pending".into();
        }
        self.save();
        // The phone push is best effort: a failed ntfy post never blocks the Discord request. It carries
        // the summary and the page link only, never the arguments.
        let pushed = match (&self.notify, &self.page) {
            (Some(n), Some(page)) => match n.publish(
                &format!("{} wants to {what}", title(agent)),
                &format!("Open to approve or deny with passkey. Request {id}."),
                &format!("{page}/r/{id}"),
            ) {
                Ok(nid) => json!(nid),
                Err(e) => json!(format!("failed: {}", e.chars().take(120).collect::<String>())),
            },
            _ => Value::Null,
        };
        audit.record(
            json!({"event": "requested", "request": id, "agent": agent, "tool": tool, "args": args, "message": msg, "reacted": reacted, "ntfy": pushed}),
        );
        Ok(json!({
            "request": id, "status": "pending", "message": self.link(&msg), "expires_in_min": self.cfg.window_secs / 60,
            "note": "Waiting for approval in Discord. Check with request_status; nothing has run yet."
        }))
    }

    /// An agent sees only its own requests.
    pub fn status(&self, agent: &str, id: &str) -> Result<Value, String> {
        let reqs = self.reqs.lock().unwrap();
        let r = reqs
            .iter()
            .find(|r| r.id == id && r.agent == agent)
            .ok_or_else(|| format!("unknown request {id}"))?;
        Ok(json!({
            "request": r.id, "tool": r.tool, "args": r.args, "status": r.status, "created": r.created,
            "decided": r.decided, "result": r.result, "message": self.link(&r.message)
        }))
    }

    fn decide(&self, id: &str, status: &str, now: u64, result: &str) {
        let mut reqs = self.reqs.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = status.into();
            r.decided = Some(now);
            r.result = Some(result.chars().take(500).collect());
        }
    }

    /// Check-and-set: move a pending, unexpired request to `to` ("approved" or "denied") and return it.
    /// Only the first caller wins; every later one (Discord, the web page, a second tap) gets None.
    pub fn claim(&self, id: &str, to: &str, by: &str, now: u64) -> Option<Request> {
        let mut reqs = self.reqs.lock().unwrap();
        let r = reqs.iter_mut().find(|r| r.id == id)?;
        if !guards::claimable(&r.status, r.created, self.cfg.window_secs, now) {
            return None;
        }
        r.status = to.into();
        r.decided = Some(now);
        r.result = Some(if to == "approved" {
            format!("approved by {by}; running")
        } else {
            format!("denied by {by}")
        });
        let out = r.clone();
        drop(reqs);
        self.save();
        Some(out)
    }

    /// A pending request as the web page shows it (None when unknown).
    pub fn get(&self, id: &str) -> Option<Request> {
        self.reqs.lock().unwrap().iter().find(|r| r.id == id).cloned()
    }

    /// Deny a claimed request: audit it and edit the Discord message.
    pub fn finish_denied(&self, r: &Request, audit: &Audit, by: &str, how: &str, now: u64) {
        audit.record(json!({"event": "denied", "request": r.id, "agent": r.agent, "tool": r.tool, "by": by}));
        let _ = self
            .discord
            .finish(&r.message, &outcome(r, "❌ **Cancelled**", &format!("Nothing ran.{how}"), now));
    }

    /// Run a claimed request's write once, record the outcome, edit the Discord message.
    pub fn execute(&self, b: &Backends, audit: &Audit, r: &Request, by: &str, how: &str, now: u64) {
        let base = json!({"request": r.id, "agent": r.agent, "tool": r.tool});
        audit.record(merge(&base, json!({"event": "approved", "by": by})));
        let (status, text) = match tools::run_write(b, &r.tool, &r.args, &r.kind) {
            Ok(v) => ("executed", v.to_string()),
            Err(e) => ("failed", format!("error: {e}")),
        };
        self.decide(&r.id, status, now, &text);
        audit.record(merge(
            &base,
            json!({"event": "executed", "ok": status == "executed", "result": text.chars().take(500).collect::<String>()}),
        ));
        self.save();
        let done = if status == "executed" {
            outcome(r, "✅ **Done**", &format!("{}{how}", done_text(r)), now)
        } else {
            outcome(
                r,
                "⚠️ **Failed**",
                &format!("It was approved but did not work: {}", text.trim_start_matches("error: ")),
                now,
            )
        };
        let _ = self.discord.finish(&r.message, &done);
    }

    /// One pass over the pending requests. Discord errors leave a request pending for the next pass.
    pub fn poll(&self, b: &Backends, audit: &Audit, now: u64) {
        let pending: Vec<Request> = self.reqs.lock().unwrap().iter().filter(|r| r.status == "pending").cloned().collect();
        for r in pending {
            // Discord calls and earlier writes in this pass take time: never judge the window by a clock read
            // before them (RACE-3, round 2).
            let now = now.max(now_secs());
            if now >= r.created + self.cfg.window_secs {
                let mut reqs = self.reqs.lock().unwrap();
                let still = reqs.iter_mut().find(|x| x.id == r.id && x.status == "pending");
                let Some(x) = still else { continue };
                x.status = "expired".into();
                x.decided = Some(now);
                x.result = Some("no decision within the window".into());
                drop(reqs);
                audit.record(json!({"event": "expired", "request": r.id, "agent": r.agent, "tool": r.tool, "why": "window"}));
                self.save();
                let _ = self
                    .discord
                    .finish(&r.message, &outcome(&r, "⌛ **Expired**", "No decision within 30 minutes. Nothing ran.", now));
                continue;
            }
            let no = match self.discord.reactors(&r.message, NO) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if guards::approver_reacted(&self.cfg.approver, &no) {
                if let Some(c) = self.claim(&r.id, "denied", "discord", now) {
                    self.finish_denied(&c, audit, &self.cfg.approver, "", now);
                }
                continue;
            }
            let yes = match self.discord.reactors(&r.message, YES) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if !guards::approver_reacted(&self.cfg.approver, &yes) {
                continue;
            }
            let now = now.max(now_secs());
            // claim before running, so neither a later pass nor the web page can run it again.
            if let Some(c) = self.claim(&r.id, "approved", "discord", now) {
                self.execute(b, audit, &c, &self.cfg.approver, "", now);
            }
        }
    }
}

/// sha256 of the args as compact JSON (serde_json's Map is sorted, so this is canonical).
pub fn args_sha256(args: &Value) -> String {
    hex::encode(Sha256::digest(args.to_string().as_bytes()))
}

/// "coder" -> "Coder".
fn title(agent: &str) -> String {
    let mut c = agent.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// The text a decided request message is edited to.
fn outcome(r: &Request, head: &str, detail: &str, now: u64) -> String {
    let what = if r.summary.is_empty() { r.tool.clone() } else { r.summary.clone() };
    format!("{head}: {} wanted to {what}.\n{detail}\n-# request {} · <t:{now}:t>", title(&r.agent), r.id)
}

fn done_text(r: &Request) -> String {
    match r.tool.as_str() {
        "jellyfin_library_scan" => "The library scan has started.".into(),
        "pve_guest_power" => "Proxmox accepted it and it is under way.".into(),
        _ => "It ran.".into(),
    }
}

fn merge(a: &Value, b: Value) -> Value {
    let mut m = a.as_object().cloned().unwrap_or_default();
    if let Value::Object(o) = b {
        m.extend(o);
    }
    Value::Object(m)
}

/// The real Discord client: REST v10 on discord.com, bot token, IPv4 only (the VM's firewall
/// allows 443 only to the nft set discord4).
pub struct HttpDiscord {
    channel: String,
    auth: String,
    agent: ureq::Agent,
}

const API: &str = "https://discord.com/api/v10";

fn enc(emoji: &str) -> String {
    emoji.bytes().map(|b| format!("%{b:02X}")).collect()
}

impl HttpDiscord {
    pub fn new(channel: &str, token: &str) -> HttpDiscord {
        let v4 = |addr: &str| -> std::io::Result<Vec<std::net::SocketAddr>> {
            use std::net::ToSocketAddrs;
            Ok(addr.to_socket_addrs()?.filter(|a| a.is_ipv4()).collect())
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .redirects(0)
            // A fresh connection every call: a pooled one goes stale while the channel is quiet.
            .max_idle_connections(0)
            .user_agent("DiscordBot (https://github.com/loafecho/agent-sandbox, 0.3)")
            .resolver(v4)
            .build();
        HttpDiscord {
            channel: channel.into(),
            auth: format!("Bot {token}"),
            agent,
        }
    }

    fn send(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        for attempt in 0..2 {
            let req = self.agent.request(method, &format!("{API}{path}")).set("Authorization", &self.auth);
            let res = match &body {
                Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
                None if method == "PUT" => req.set("Content-Length", "0").call(),
                None => req.call(),
            };
            match res {
                Ok(r) => {
                    let t = r.into_string().unwrap_or_default();
                    return Ok(serde_json::from_str(&t).unwrap_or(Value::Null));
                }
                Err(ureq::Error::Status(429, r)) if attempt == 0 => {
                    let wait = r
                        .into_string()
                        .ok()
                        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                        .and_then(|v| v["retry_after"].as_f64())
                        .unwrap_or(1.0);
                    std::thread::sleep(std::time::Duration::from_millis((wait.min(5.0) * 1000.0) as u64 + 100));
                }
                Err(ureq::Error::Status(code, _)) => return Err(format!("discord HTTP {code}")),
                // Retry a transport error once. A POST is retried only when it never connected, so a
                // request is never posted twice.
                Err(ureq::Error::Transport(t))
                    if attempt == 0 && (method != "POST" || matches!(t.kind(), ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed)) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(ureq::Error::Transport(t)) => return Err(format!("discord transport error: {}", t.kind())),
            }
        }
        Err("discord: gave up after a retry".into())
    }
}

impl Discord for HttpDiscord {
    fn post(&self, content: &str, mention: &str) -> Result<String, String> {
        let v = self.send(
            "POST",
            &format!("/channels/{}/messages", self.channel),
            Some(json!({"content": content, "allowed_mentions": {"parse": [], "users": [mention]}})),
        )?;
        v["id"].as_str().map(String::from).ok_or_else(|| "discord: no message id".into())
    }

    fn react(&self, msg: &str, emoji: &str) -> Result<(), String> {
        self.send("PUT", &format!("/channels/{}/messages/{msg}/reactions/{}/@me", self.channel, enc(emoji)), None)
            .map(|_| ())
    }

    fn reactors(&self, msg: &str, emoji: &str) -> Result<Vec<String>, String> {
        let v = self.send(
            "GET",
            &format!("/channels/{}/messages/{msg}/reactions/{}?limit=100", self.channel, enc(emoji)),
            None,
        )?;
        Ok(v.as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|u| u["id"].as_str().map(String::from))
            .collect())
    }

    fn finish(&self, msg: &str, content: &str) -> Result<(), String> {
        self.send(
            "PATCH",
            &format!("/channels/{}/messages/{msg}", self.channel),
            Some(json!({"content": content, "allowed_mentions": {"parse": []}})),
        )
        .map(|_| ())
    }
}
