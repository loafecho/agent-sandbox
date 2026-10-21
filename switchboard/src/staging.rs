//! Staging build only (`--features staging`, workstation tests). Fakes that live in files next to the
//! audit log, so an end-to-end script can play the approver's Discord ✅ and count writes:
//!   fake-discord.json   {"posts": [...], "reactions": {"<msg> <emoji>": [user ids]}, "edits": [...]}
//!   ntfy.jsonl          one line per phone push
//!   writes.log          one line per write that ran (jellyfin/refresh, pve/<kind>/<vmid>/<action>)
//! install.sh refuses a staging binary (`switchboard version` says build=staging).

use crate::approve::{Discord, Notify};
use crate::config::Config;
use crate::tools::{Backends, JfWrite, JsonGet, PowerAction, Prom, PveWrite, Sample};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

fn dir(cfg: &Config) -> PathBuf {
    std::path::Path::new(&cfg.audit_log).parent().map(|p| p.to_path_buf()).unwrap_or_default()
}

fn append(path: &PathBuf, line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

struct FakeProm;
impl Prom for FakeProm {
    fn query(&self, _q: &str) -> Result<Vec<Sample>, String> {
        Ok(vec![Sample {
            labels: Default::default(),
            value: 42.0,
        }])
    }
}

struct FakeJson;
impl JsonGet for FakeJson {
    fn get(&self, path: &str, _q: &[(&str, &str)]) -> Result<Value, String> {
        match path {
            "/Items/Counts" => Ok(json!({"MovieCount": 1})),
            "/cluster/resources" => Ok(json!([{"vmid": 103, "type": "lxc", "name": "telemetry"}])),
            _ => Ok(json!([])),
        }
    }
}

struct FakeWrites(PathBuf);
impl JfWrite for FakeWrites {
    fn library_refresh(&self) -> Result<(), String> {
        append(&self.0, "jellyfin/refresh");
        Ok(())
    }
}
impl PveWrite for FakeWrites {
    fn power(&self, node: &str, kind: &str, vmid: &str, action: PowerAction) -> Result<(), String> {
        append(&self.0, &format!("pve/{node}/{kind}/{vmid}/{}", action.as_str()));
        Ok(())
    }
}

pub fn backends(cfg: &Config) -> Backends {
    let w = dir(cfg).join("writes.log");
    Backends {
        prom: Box::new(FakeProm),
        pve: cfg.pve.as_ref().map(|_| Box::new(FakeJson) as Box<dyn JsonGet>),
        pve_node: "pve1".into(),
        jellyfin: cfg.jellyfin.as_ref().map(|_| Box::new(FakeJson) as Box<dyn JsonGet>),
        pve_power: Some(Box::new(FakeWrites(w.clone()))),
        jf_write: Some(Box::new(FakeWrites(w))),
    }
}

struct FakeDiscord {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FakeDiscord {
    fn load(&self) -> Value {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({"posts": [], "reactions": {}, "edits": []}))
    }
    fn store(&self, v: &Value) {
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

impl Discord for FakeDiscord {
    fn post(&self, content: &str, _m: &str) -> Result<String, String> {
        let _g = self.lock.lock().unwrap();
        let mut v = self.load();
        let posts = v["posts"].as_array_mut().ok_or("bad fake")?;
        posts.push(json!(content));
        let id = format!("fake-{}", posts.len());
        self.store(&v);
        Ok(id)
    }
    fn react(&self, msg: &str, emoji: &str) -> Result<(), String> {
        let _g = self.lock.lock().unwrap();
        let mut v = self.load();
        let k = format!("{msg} {emoji}");
        let list = v["reactions"].as_object_mut().ok_or("bad fake")?.entry(k).or_insert(json!([]));
        list.as_array_mut().ok_or("bad fake")?.push(json!("bot"));
        self.store(&v);
        Ok(())
    }
    fn reactors(&self, msg: &str, emoji: &str) -> Result<Vec<String>, String> {
        let _g = self.lock.lock().unwrap();
        let v = self.load();
        Ok(v["reactions"][format!("{msg} {emoji}")]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default())
    }
    fn finish(&self, msg: &str, content: &str) -> Result<(), String> {
        let _g = self.lock.lock().unwrap();
        let mut v = self.load();
        if let Some(e) = v["edits"].as_array_mut() {
            e.push(json!({"message": msg, "content": content}));
        }
        self.store(&v);
        Ok(())
    }
}

struct FakeNtfy(PathBuf, Mutex<u64>);
impl Notify for FakeNtfy {
    fn publish(&self, title: &str, message: &str, click: &str) -> Result<String, String> {
        let mut n = self.1.lock().unwrap();
        *n += 1;
        let id = format!("ntfy-fake-{n}");
        append(&self.0, &json!({"id": id, "title": title, "message": message, "click": click}).to_string());
        Ok(id)
    }
}

pub fn discord_and_notify(cfg: &Config) -> (Box<dyn Discord>, Option<Box<dyn Notify>>) {
    let d = dir(cfg);
    (
        Box::new(FakeDiscord {
            path: d.join("fake-discord.json"),
            lock: Mutex::new(()),
        }),
        Some(Box::new(FakeNtfy(d.join("ntfy.jsonl"), Mutex::new(0)))),
    )
}
