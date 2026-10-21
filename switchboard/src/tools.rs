//! Tools. Every request is built here from validated arguments; the agent never supplies a query, a
//! path or a URL. Backends: Prometheus (no key), Proxmox and Jellyfin (the switchboard's own keys,
//! read from its environment). The read traits have a `get` and nothing else. The only writes are
//! the two write types below (`PveWrite`, `JfWrite`), each with exactly its listed calls, and they
//! run only from an approved request (approve.rs), never straight from a tool call.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const IMPLEMENTED: &[&str] = &[
    "host_health",
    "guest_list",
    "services_up",
    "pve_node_status",
    "pve_recent_tasks",
    "jellyfin_library_counts",
    "jellyfin_sessions",
    "pve_guest_power",
    "jellyfin_library_scan",
    "request_status",
];

/// The three power actions. There is no hard stop.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PowerAction {
    Start,
    Shutdown,
    Reboot,
}

impl PowerAction {
    pub fn parse(s: &str) -> Option<PowerAction> {
        match s {
            "start" => Some(PowerAction::Start),
            "shutdown" => Some(PowerAction::Shutdown),
            "reboot" => Some(PowerAction::Reboot),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            PowerAction::Start => "start",
            PowerAction::Shutdown => "shutdown",
            PowerAction::Reboot => "reboot",
        }
    }
}

/// Proxmox writes: guest power and nothing else, with the separate `power` token
/// (role SwitchboardPower: VM.PowerMgmt + VM.Audit on the allowlisted guests only).
pub trait PveWrite: Send + Sync {
    /// kind is "qemu" or "lxc".
    fn power(&self, node: &str, kind: &str, vmid: &str, action: PowerAction) -> Result<(), String>;
}

/// Jellyfin writes: a library scan and nothing else.
pub trait JfWrite: Send + Sync {
    fn library_refresh(&self) -> Result<(), String>;
}

/// A JSON API the switchboard may only read from.
pub trait JsonGet: Send + Sync {
    fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, String>;
}

pub struct Backends {
    pub prom: Box<dyn Prom>,
    pub pve: Option<Box<dyn JsonGet>>,
    pub pve_node: String,
    pub jellyfin: Option<Box<dyn JsonGet>>,
    pub pve_power: Option<Box<dyn PveWrite>>,
    pub jf_write: Option<Box<dyn JfWrite>>,
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

pub trait Prom: Send + Sync {
    fn query(&self, q: &str) -> Result<Vec<Sample>, String>;
}

/// Real backend: GET {base}/api/v1/query. Nothing else is ever requested.
pub struct HttpProm {
    pub base: String,
    agent: ureq::Agent,
}

impl HttpProm {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).build();
        HttpProm {
            base: base.trim_end_matches('/').to_string(),
            agent,
        }
    }
}

impl Prom for HttpProm {
    fn query(&self, q: &str) -> Result<Vec<Sample>, String> {
        let resp = self
            .agent
            .get(&format!("{}/api/v1/query", self.base))
            .query("query", q)
            .call()
            .map_err(|e| format!("prometheus: {e}"))?;
        let text = resp.into_string().map_err(|e| format!("prometheus read: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("prometheus json: {e}"))?;
        if v["status"] != "success" {
            return Err("prometheus returned an error".into());
        }
        let mut out = Vec::new();
        for r in v["data"]["result"].as_array().cloned().unwrap_or_default() {
            let labels = r["metric"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                .unwrap_or_default();
            let value = r["value"][1].as_str().and_then(|s| s.parse().ok()).unwrap_or(f64::NAN);
            out.push(Sample { labels, value });
        }
        Ok(out)
    }
}

/// GET-only HTTP JSON client with one fixed auth header. The header value is never logged or
/// returned; errors carry only the status or the transport error.
pub struct HttpJson {
    base: String,
    header: (&'static str, String),
    agent: ureq::Agent,
    unwrap_data: bool,
}

impl HttpJson {
    /// Proxmox: TLS verified against exactly one CA (the cluster's pve-root-ca.pem), token auth.
    pub fn pve(base: &str, ca_file: &str, token_id: &str, secret: &str) -> Result<Self, String> {
        Ok(HttpJson {
            base: base.trim_end_matches('/').to_string(),
            header: ("Authorization", format!("PVEAPIToken={token_id}={secret}")),
            agent: pve_agent(ca_file)?,
            unwrap_data: true,
        })
    }

    /// Jellyfin: plain HTTP on the LAN, app key in X-Emby-Token.
    pub fn jellyfin(base: &str, key: &str) -> Self {
        HttpJson {
            base: base.trim_end_matches('/').to_string(),
            header: ("X-Emby-Token", key.to_string()),
            agent: lan_agent(),
            unwrap_data: false,
        }
    }
}

fn lan_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).redirects(0).build()
}

fn pve_agent(ca_file: &str) -> Result<ureq::Agent, String> {
    let pem = std::fs::read(ca_file).map_err(|e| format!("read {ca_file}: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(c.map_err(|e| format!("{ca_file}: {e}"))?).map_err(|e| format!("{ca_file}: {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!("{ca_file}: no certificate"));
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls))
        .timeout(std::time::Duration::from_secs(10))
        .redirects(0)
        .build())
}

fn http_err(path: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code} from {path}"),
        ureq::Error::Transport(t) => format!("transport error on {path}: {}", t.kind()),
    }
}

/// The real PveWrite: POST .../status/{start|shutdown|reboot}, nothing else.
pub struct HttpPvePower {
    base: String,
    auth: String,
    agent: ureq::Agent,
}

impl HttpPvePower {
    pub fn new(base: &str, ca_file: &str, token_id: &str, secret: &str) -> Result<Self, String> {
        Ok(HttpPvePower {
            base: base.trim_end_matches('/').to_string(),
            auth: format!("PVEAPIToken={token_id}={secret}"),
            agent: pve_agent(ca_file)?,
        })
    }
}

impl PveWrite for HttpPvePower {
    fn power(&self, node: &str, kind: &str, vmid: &str, action: PowerAction) -> Result<(), String> {
        if !(kind == "qemu" || kind == "lxc") || vmid.is_empty() || !vmid.chars().all(|c| c.is_ascii_digit()) {
            return Err("bad guest".into());
        }
        let path = format!("/nodes/{node}/{kind}/{vmid}/status/{}", action.as_str());
        self.agent
            .post(&format!("{}{}", self.base, path))
            .set("Authorization", &self.auth)
            .send_form(&[])
            .map_err(|e| http_err(&path, e))?;
        Ok(())
    }
}

/// The real JfWrite: POST /Library/Refresh, nothing else.
pub struct HttpJfWrite {
    base: String,
    key: String,
    agent: ureq::Agent,
}

impl HttpJfWrite {
    pub fn new(base: &str, key: &str) -> Self {
        HttpJfWrite {
            base: base.trim_end_matches('/').to_string(),
            key: key.to_string(),
            agent: lan_agent(),
        }
    }
}

impl JfWrite for HttpJfWrite {
    fn library_refresh(&self) -> Result<(), String> {
        let path = "/Library/Refresh";
        self.agent
            .post(&format!("{}{}", self.base, path))
            .set("X-Emby-Token", &self.key)
            .call()
            .map_err(|e| http_err(path, e))?;
        Ok(())
    }
}

impl JsonGet for HttpJson {
    fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, String> {
        let mut req = self.agent.get(&format!("{}{}", self.base, path)).set(self.header.0, &self.header.1);
        for (k, v) in query {
            req = req.query(k, v);
        }
        let resp = req.call().map_err(|e| http_err(path, e))?;
        let text = resp.into_string().map_err(|e| format!("read {path}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|_| format!("{path}: not JSON"))?;
        Ok(if self.unwrap_data { v["data"].clone() } else { v })
    }
}

fn first(p: &dyn Prom, q: &str) -> Result<Option<f64>, String> {
    Ok(p.query(q)?.first().map(|s| s.value).filter(|v| v.is_finite()))
}

fn gib(b: Option<f64>) -> Value {
    b.map(|v| json!((v / 1073741824.0 * 100.0).round() / 100.0)).unwrap_or(Value::Null)
}

pub fn run(b: &Backends, tool: &str, args: &Value) -> Result<Value, String> {
    let p = b.prom.as_ref();
    let pve = || b.pve.as_deref().ok_or_else(|| "proxmox backend is not configured".to_string());
    let jf = || b.jellyfin.as_deref().ok_or_else(|| "jellyfin backend is not configured".to_string());
    match tool {
        "host_health" => host_health(p, args["host"].as_str().unwrap_or("")),
        "guest_list" => guest_list(p),
        "services_up" => services_up(p),
        "pve_node_status" => pve_node_status(pve()?, &b.pve_node),
        "pve_recent_tasks" => pve_recent_tasks(pve()?, &b.pve_node, args["limit"].as_str().unwrap_or("10")),
        "jellyfin_library_counts" => jellyfin_library_counts(jf()?),
        "jellyfin_sessions" => jellyfin_sessions(jf()?),
        "pve_guest_power" | "jellyfin_library_scan" | "request_status" => Err(format!("{tool} runs only through an approval")),
        _ => Err(format!("no implementation for {tool}")),
    }
}

fn round1(v: &Value) -> Value {
    v.as_f64().map(|f| json!((f * 10.0).round() / 10.0)).unwrap_or(Value::Null)
}

/// Fields picked one by one; nothing is passed through wholesale.
fn pve_node_status(pve: &dyn JsonGet, node: &str) -> Result<Value, String> {
    let d = pve.get(&format!("/nodes/{node}/status"), &[])?;
    Ok(json!({
        "node": node,
        "uptime_s": d["uptime"],
        "cpu_busy_pct": round1(&json!(d["cpu"].as_f64().map(|c| c * 100.0))),
        "cpus": d["cpuinfo"]["cpus"],
        "cpu_model": d["cpuinfo"]["model"],
        "loadavg": d["loadavg"],
        "mem_total_gib": gib(d["memory"]["total"].as_f64()),
        "mem_used_gib": gib(d["memory"]["used"].as_f64()),
        "swap_used_gib": gib(d["swap"]["used"].as_f64()),
        "rootfs_total_gib": gib(d["rootfs"]["total"].as_f64()),
        "rootfs_used_gib": gib(d["rootfs"]["used"].as_f64()),
        "pve_version": d["pveversion"],
        "kernel": d["kversion"],
    }))
}

/// `limit` has already passed its pattern guard (1-50). Newest first, as Proxmox returns them.
fn pve_recent_tasks(pve: &dyn JsonGet, node: &str, limit: &str) -> Result<Value, String> {
    let d = pve.get(&format!("/nodes/{node}/tasks"), &[("limit", limit)])?;
    let n: usize = limit.parse().unwrap_or(10);
    let tasks: Vec<Value> = d
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .take(n)
        .map(|t| {
            json!({
                "type": t["type"], "id": t["id"], "user": t["user"], "status": t["status"],
                "starttime": t["starttime"], "endtime": t["endtime"],
            })
        })
        .collect();
    Ok(json!({"node": node, "count": tasks.len(), "tasks": tasks}))
}

fn jellyfin_library_counts(jf: &dyn JsonGet) -> Result<Value, String> {
    let d = jf.get("/Items/Counts", &[])?;
    let counts: Map<String, Value> = d
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, v)| k.ends_with("Count") && v.is_u64())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    if counts.is_empty() {
        return Err("jellyfin returned no counts".into());
    }
    Ok(Value::Object(counts))
}

/// Who is watching what. IP addresses, device ids, session and user ids are dropped.
fn jellyfin_sessions(jf: &dyn JsonGet) -> Result<Value, String> {
    let d = jf.get("/Sessions", &[("activeWithinSeconds", "960")])?;
    let sessions: Vec<Value> = d
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let np = &s["NowPlayingItem"];
            json!({
                "user": s["UserName"],
                "client": s["Client"],
                "device": s["DeviceName"],
                "last_activity": s["LastActivityDate"],
                "now_playing": if np.is_object() {
                    json!({"name": np["Name"], "type": np["Type"], "series": np["SeriesName"], "paused": s["PlayState"]["IsPaused"]})
                } else { Value::Null },
            })
        })
        .collect();
    let playing = sessions.iter().filter(|s| !s["now_playing"].is_null()).count();
    Ok(json!({"count": sessions.len(), "playing": playing, "sessions": sessions}))
}

/// `host` has already passed the ^[a-z0-9-]{1,32}$ guard, so it is safe inside a label matcher.
fn host_health(p: &dyn Prom, host: &str) -> Result<Value, String> {
    let sel = format!("host=\"{host}\"");
    let cpu = first(p, &format!("100 * (1 - avg(rate(node_cpu_seconds_total{{mode=\"idle\",{sel}}}[5m])))"))?;
    let mem_total = first(p, &format!("node_memory_MemTotal_bytes{{{sel}}}"))?;
    let mem_avail = first(p, &format!("node_memory_MemAvailable_bytes{{{sel}}}"))?;
    let disk_size = first(p, &format!("node_filesystem_size_bytes{{{sel},mountpoint=\"/\"}}"))?;
    let disk_avail = first(p, &format!("node_filesystem_avail_bytes{{{sel},mountpoint=\"/\"}}"))?;
    if mem_total.is_none() && cpu.is_none() {
        return Err(format!("no metrics for host {host}"));
    }
    Ok(json!({
        "host": host,
        "cpu_busy_pct": cpu.map(|v| (v * 10.0).round() / 10.0),
        "mem_total_gib": gib(mem_total),
        "mem_available_gib": gib(mem_avail),
        "root_disk_size_gib": gib(disk_size),
        "root_disk_free_gib": gib(disk_avail),
    }))
}

fn guest_list(p: &dyn Prom) -> Result<Value, String> {
    let up = p.query("pve_guest_up")?;
    let mem: BTreeMap<String, f64> = p
        .query("pve_guest_memory_max_bytes")?
        .into_iter()
        .map(|s| (s.labels.get("vmid").cloned().unwrap_or_default(), s.value))
        .collect();
    let mut guests: Vec<Value> = up
        .iter()
        .map(|s| {
            let vmid = s.labels.get("vmid").cloned().unwrap_or_default();
            json!({
                "vmid": vmid.parse::<u32>().unwrap_or(0),
                "name": s.labels.get("guest").cloned().unwrap_or_default(),
                "kind": s.labels.get("kind").cloned().unwrap_or_default(),
                "state": if s.value >= 1.0 { "running" } else { "stopped" },
                "mem_max_gib": gib(mem.get(&vmid).copied()),
            })
        })
        .collect();
    guests.sort_by_key(|g| g["vmid"].as_u64().unwrap_or(0));
    Ok(json!({"count": guests.len(), "guests": guests}))
}

fn services_up(p: &dyn Prom) -> Result<Value, String> {
    let mut targets: Vec<Value> = p
        .query("up")?
        .iter()
        .map(|s| {
            json!({
                "job": s.labels.get("job").cloned().unwrap_or_default(),
                "instance": s.labels.get("instance").cloned().unwrap_or_default(),
                "service": s.labels.get("service").or(s.labels.get("host")).cloned().unwrap_or_default(),
                "up": s.value >= 1.0,
            })
        })
        .collect();
    targets.sort_by(|a, b| {
        a["job"]
            .as_str()
            .cmp(&b["job"].as_str())
            .then(a["instance"].as_str().cmp(&b["instance"].as_str()))
    });
    let down = targets.iter().filter(|t| t["up"] == false).count();
    Ok(json!({"count": targets.len(), "down": down, "targets": targets}))
}

/// Find a guest's kind and name with the read token (GET /cluster/resources). Used before an
/// approval is posted, so the message names the guest and an unknown vmid is refused early.
pub fn pve_guest(pve: &dyn JsonGet, vmid: &str) -> Result<(String, String), String> {
    let d = pve.get("/cluster/resources", &[("type", "vm")])?;
    for g in d.as_array().cloned().unwrap_or_default() {
        if g["vmid"].as_u64().map(|v| v.to_string()).as_deref() == Some(vmid) {
            let kind = g["type"].as_str().unwrap_or("").to_string();
            if kind != "qemu" && kind != "lxc" {
                return Err(format!("guest {vmid} has unknown type"));
            }
            return Ok((kind, g["name"].as_str().unwrap_or("").to_string()));
        }
    }
    Err(format!("no guest {vmid} on proxmox"))
}

/// Run an approved write. Called only by approve.rs after the approver's ✅.
pub fn run_write(b: &Backends, tool: &str, args: &Value, kind: &str) -> Result<Value, String> {
    match tool {
        "pve_guest_power" => {
            let w = b.pve_power.as_deref().ok_or("proxmox power backend is not configured")?;
            let action = PowerAction::parse(args["action"].as_str().unwrap_or("")).ok_or("bad action")?;
            let vmid = args["vmid"].as_str().unwrap_or("");
            w.power(&b.pve_node, kind, vmid, action)?;
            Ok(json!({"vmid": vmid, "action": action.as_str(), "result": "task started"}))
        }
        "jellyfin_library_scan" => {
            b.jf_write.as_deref().ok_or("jellyfin write backend is not configured")?.library_refresh()?;
            Ok(json!({"result": "library scan started"}))
        }
        _ => Err(format!("{tool} is not a write")),
    }
}
