//! Runtime config. `generated/agents.json` (from tools.yaml via gen.py) carries the tools and which
//! agent may call which; deploy/install.sh merges in each agent's token sha256 and the host settings.
//! The config never holds a token value, only its sha256.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub allowed_sources: Vec<String>,
    pub prometheus: String,
    pub audit_log: String,
    /// Proxmox API (keys come from the environment: PVE_TOKEN_ID, PVE_TOKEN_SECRET).
    #[serde(default)]
    pub pve: Option<PveCfg>,
    /// Jellyfin base URL (key from the environment: JELLYFIN_API_KEY).
    #[serde(default)]
    pub jellyfin: Option<String>,
    /// Approve tier: where requests are posted and who may approve (bot token from DISCORD_BOT_TOKEN).
    #[serde(default)]
    pub approvals: Option<ApprovalsCfg>,
    /// Guests pve_guest_power may act on (sbsecrets.py POWER_VMIDS, copied in by gen.py).
    #[serde(default)]
    pub power_vmids: Vec<String>,
    /// Upstream MCP gateways forwarded tools go to (keys from the environment: each backend's token_env).
    #[serde(default)]
    pub backends: BTreeMap<String, UpstreamCfg>,
    /// The passkey approval page (WebAuthn), served on 127.0.0.1 and published by `tailscale serve`.
    #[serde(default)]
    pub web: Option<WebCfg>,
    /// Phone notification for each approval request (token from NTFY_TOKEN).
    #[serde(default)]
    pub ntfy: Option<NtfyCfg>,
    pub agents: BTreeMap<String, Agent>,
    pub tools: BTreeMap<String, ToolSpec>,
}

/// One existing upstream MCP gateway. `group` names the tool set it serves (media, janitor); several
/// backends may serve one group (the real pipeline and the eval fixture).
#[derive(Deserialize, Clone, Debug)]
pub struct UpstreamCfg {
    pub group: String,
    pub url: String,
    pub token_env: String,
    /// Default per-call timeout; `slow` overrides it per tool (search_media takes minutes).
    pub timeout_secs: u64,
    #[serde(default)]
    pub slow: BTreeMap<String, u64>,
    /// At most this many calls of one tool in flight on this backend at once (default 4; search_media 1).
    #[serde(default)]
    pub max_inflight: BTreeMap<String, usize>,
    /// The eval fixture: only eval agents reach it, and eval agents reach nothing else.
    #[serde(default)]
    pub eval: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct WebCfg {
    pub listen: String,
    /// The only callers the page answers: the approver's phone's tailnet addresses (as tailscale serve reports them).
    pub allow_src: Vec<String>,
    pub rp_id: String,
    pub origin: String,
    pub credentials_file: String,
    pub enroll_file: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct NtfyCfg {
    /// e.g. https://ntfy.tailnet.example
    pub url: String,
    pub topic: String,
    /// Connect to this IP (the ntfy tailnet address) whatever DNS says; TLS still checks the name.
    #[serde(default)]
    pub pin_ip: Option<String>,
}

/// The only rpId and origin a production build accepts.
pub const PROD_RP_ID: &str = "switchboard.tailnet.example";
pub const PROD_ORIGIN: &str = "https://switchboard.tailnet.example";
pub const STAGING: bool = cfg!(feature = "staging");

#[derive(Deserialize, Clone, Debug)]
pub struct ApprovalsCfg {
    pub guild: String,
    pub channel: String,
    /// The one Discord user whose ✅/❌ counts.
    pub approver: String,
    pub window_secs: u64,
    pub max_pending: usize,
    pub state_file: String,
}

/// Guests no agent may ever power, whatever the allowlist says: losing any of them cuts the
/// approval path (the workstation, the secrets store, the agent host, the switchboard itself).
pub const NEVER_POWER: &[&str] = &["100", "101", "150", "160"];

#[derive(Deserialize, Clone, Debug)]
pub struct PveCfg {
    pub base: String,
    pub node: String,
    /// The only CA trusted for the Proxmox API (the cluster's pve-root-ca.pem).
    pub ca_file: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Agent {
    pub token_sha256: String,
    pub tools: Vec<String>,
    pub rate_per_min: u32,
    /// Forwarded tool group -> the one backend this agent's calls go to (media-eval: media -> media_fixture).
    #[serde(default)]
    pub forward: BTreeMap<String, String>,
    /// An eval agent: may forward only to eval backends, and no other agent may (AUTHZ-1, round 2).
    #[serde(default)]
    pub eval: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ToolSpec {
    pub tier: String,
    pub description: String,
    #[serde(default)]
    pub args: BTreeMap<String, ArgSpec>,
    /// Tier forward: the tool group (media, janitor) and the upstream's own inputSchema, copied byte for byte.
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ArgSpec {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let cfg: Config = serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Refuse to start on a config that would widen access by accident.
    pub fn validate(&self) -> Result<(), String> {
        let mut hashes = std::collections::BTreeSet::new();
        for (name, a) in &self.agents {
            if !hashes.insert(a.token_sha256.to_ascii_lowercase()) {
                return Err(format!("agent {name}: token_sha256 is shared with another agent"));
            }
            for (g, b) in &a.forward {
                match self.backends.get(b) {
                    Some(u) if u.group == *g && u.eval == a.eval => {}
                    Some(_) => return Err(format!("agent {name}: forward.{g} -> {b} mixes eval and real backends or groups")),
                    None => return Err(format!("agent {name}: forward.{g} -> unknown backend {b}")),
                }
            }
            if !a.forward.is_empty() {
                if let Some(t) = a.tools.iter().find(|t| self.tools.get(*t).map(|x| x.tier != "forward").unwrap_or(false)) {
                    return Err(format!("agent {name}: a forwarded agent may hold forwarded tools only, not {t}"));
                }
            }
            if a.token_sha256.len() != 64 || hex::decode(&a.token_sha256).is_err() {
                return Err(format!("agent {name}: token_sha256 must be 64 hex chars"));
            }
            for t in &a.tools {
                if !self.tools.contains_key(t) {
                    return Err(format!("agent {name}: tool {t} is not defined"));
                }
            }
            if a.rate_per_min == 0 {
                return Err(format!("agent {name}: rate_per_min must be > 0"));
            }
        }
        for (name, t) in &self.tools {
            if t.tier == "forward" {
                let g = t.upstream.as_deref().unwrap_or("");
                if g.is_empty() || !t.input_schema.as_ref().map(|v| v.is_object()).unwrap_or(false) || !t.args.is_empty() {
                    return Err(format!("tool {name}: tier forward needs upstream and input_schema, and no args"));
                }
                for (an, a) in &self.agents {
                    if a.tools.contains(name)
                        && !a
                            .forward
                            .get(g)
                            .map(|b| self.backends.get(b).map(|u| u.group == g).unwrap_or(false))
                            .unwrap_or(false)
                    {
                        return Err(format!("agent {an}: tool {name} needs forward.{g} -> a {g} backend"));
                    }
                }
                continue;
            }
            if !crate::tools::IMPLEMENTED.contains(&name.as_str()) {
                return Err(format!("tool {name} is in the config but has no implementation"));
            }
            if name.starts_with("pve_") && self.pve.is_none() {
                return Err(format!("tool {name} needs the pve backend in the config"));
            }
            if name.starts_with("jellyfin_") && self.jellyfin.is_none() {
                return Err(format!("tool {name} needs the jellyfin backend in the config"));
            }
            if let Some(p) = &self.pve {
                if !p.base.starts_with("https://") || p.node.is_empty() || !p.node.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err("pve: base must be https:// and node a plain name".into());
                }
            }
            match t.tier.as_str() {
                "read" => {}
                "forward" => {}
                "approve" => {
                    if self.approvals.is_none() {
                        return Err(format!("tool {name}: tier approve needs the approvals section"));
                    }
                }
                other => return Err(format!("tool {name}: tier {other} is not supported (read, approve)")),
            }
            if name == "request_status" && self.approvals.is_none() {
                return Err("tool request_status needs the approvals section".into());
            }
            if name == "pve_guest_power" {
                if self.power_vmids.is_empty() {
                    return Err("tool pve_guest_power needs a non-empty power_vmids".into());
                }
                if let Some(v) = self.power_vmids.iter().find(|v| NEVER_POWER.contains(&v.as_str())) {
                    return Err(format!("power_vmids holds {v}, which may never be powered by an agent"));
                }
            }
            for (arg, spec) in &t.args {
                if spec.ty != "string" {
                    return Err(format!("tool {name} arg {arg}: only string args in v0"));
                }
                if spec.pattern.is_none() {
                    return Err(format!("tool {name} arg {arg}: every string arg needs a pattern"));
                }
            }
        }
        for (name, b) in &self.backends {
            if !b.url.starts_with("http://") || !b.url.ends_with("/mcp") || b.timeout_secs == 0 || b.slow.values().any(|v| *v == 0) {
                return Err(format!("backend {name}: url must be http://.../mcp and timeouts > 0"));
            }
            if b.token_env.is_empty() || !b.token_env.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                return Err(format!("backend {name}: token_env must be an env var name"));
            }
        }
        if let Some(w) = &self.web {
            if self.approvals.is_none() {
                return Err("web: needs the approvals section".into());
            }
            if w.allow_src.is_empty() || w.allow_src.iter().any(|a| a.parse::<std::net::IpAddr>().is_err()) {
                return Err("web: allow_src must list the phone's tailnet IPs".into());
            }
            if !w.listen.starts_with("127.0.0.1:") {
                return Err("web: listen must be on 127.0.0.1 (tailscale serve publishes it)".into());
            }
            let ok = if STAGING {
                w.rp_id == "localhost"
            } else {
                w.rp_id == PROD_RP_ID && w.origin == PROD_ORIGIN
            };
            if !ok {
                return Err(format!("web: rp_id/origin must be {PROD_RP_ID} / {PROD_ORIGIN} (staging builds: localhost)"));
            }
        }
        if let Some(n) = &self.ntfy {
            if !n.url.starts_with("https://") || n.topic.is_empty() || !n.topic.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err("ntfy: url must be https:// and topic a plain name".into());
            }
        }
        if let Some(a) = &self.approvals {
            let num = |s: &str| !s.is_empty() && s.len() <= 20 && s.chars().all(|c| c.is_ascii_digit());
            if !num(&a.guild) || !num(&a.channel) || !num(&a.approver) {
                return Err("approvals: guild, channel and approver must be Discord ids".into());
            }
            if a.window_secs == 0 || a.max_pending == 0 {
                return Err("approvals: window_secs and max_pending must be > 0".into());
            }
        }
        Ok(())
    }
}
