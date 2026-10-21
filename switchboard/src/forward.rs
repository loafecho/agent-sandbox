//! Forwarded tools: an agent's calls to its own gateway's tools go on, unchanged, to the MCP gateway that
//! already guards them (in the tests: a media gateway, its eval fixture, and a janitor gateway). This is a
//! minimal MCP client: one JSON-RPC `tools/call` POST per call, the backend's own bearer token (from the
//! switchboard's environment), the upstream's result passed back as is. The gateways keep every guard
//! of their own; the switchboard adds the token -> tools -> backend
//! check (guards::backend, RED_BACKEND) and in-flight caps in front of them. The
//! gateways need no MCP session, so there is no initialize round trip.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

pub const MAX_REPLY: u64 = 1024 * 1024;

pub trait Upstream: Send + Sync {
    /// Returns the MCP `result` object ({content, isError}).
    fn call(&self, tool: &str, args: &Value, timeout: Duration) -> Result<Value, String>;
}

pub struct HttpUpstream {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

impl HttpUpstream {
    pub fn new(url: &str, token: &str) -> HttpUpstream {
        HttpUpstream {
            url: url.into(),
            auth: format!("Bearer {token}"),
            agent: ureq::AgentBuilder::new().redirects(0).max_idle_connections(0).build(),
        }
    }
}

impl Upstream for HttpUpstream {
    fn call(&self, tool: &str, args: &Value, timeout: Duration) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
        let r = self
            .agent
            .post(&self.url)
            .timeout(timeout)
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| match e {
                ureq::Error::Status(c, _) => format!("upstream HTTP {c}"),
                ureq::Error::Transport(t) => format!("upstream transport error: {}", t.kind()),
            })?;
        let mut text = String::new();
        r.into_reader()
            .take(MAX_REPLY + 1)
            .read_to_string(&mut text)
            .map_err(|_| "upstream reply unreadable".to_string())?;
        if text.len() as u64 > MAX_REPLY {
            return Err("upstream reply over 1 MiB".into());
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| "upstream reply is not JSON".to_string())?;
        if let Some(e) = v.get("error") {
            return Err(format!(
                "upstream error: {}",
                e["message"].as_str().unwrap_or("?").chars().take(200).collect::<String>()
            ));
        }
        let res = v.get("result").cloned().ok_or("upstream reply has no result")?;
        if !res["content"].is_array() {
            return Err("upstream result has no content".into());
        }
        Ok(res)
    }
}

/// Counts calls in flight per key ("backend/tool" and "agent:<name>"). `enter` refuses at the cap
/// instead of queueing, so a slow tool can never pile up threads.
pub struct InFlight {
    m: Mutex<HashMap<String, usize>>,
}

pub struct Slot<'a> {
    owner: &'a InFlight,
    keys: Vec<String>,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut m = self.owner.m.lock().unwrap();
        for k in &self.keys {
            if let Some(n) = m.get_mut(k) {
                *n = n.saturating_sub(1);
            }
        }
    }
}

impl InFlight {
    pub fn new() -> Self {
        InFlight { m: Mutex::new(HashMap::new()) }
    }

    pub fn enter(&self, caps: &[(String, usize)]) -> Option<Slot<'_>> {
        let mut m = self.m.lock().unwrap();
        if caps.iter().any(|(k, cap)| m.get(k).copied().unwrap_or(0) >= *cap) {
            return None;
        }
        for (k, _) in caps {
            *m.entry(k.clone()).or_default() += 1;
        }
        Some(Slot {
            owner: self,
            keys: caps.iter().map(|(k, _)| k.clone()).collect(),
        })
    }
}
