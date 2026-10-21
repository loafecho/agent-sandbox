//! Append-only, hash-chained audit log (JSON lines). Each line carries `prev` (the previous line's
//! hash) and `hash` = sha256(prev + the line's JSON without `hash`). `verify` walks the chain.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS: &str = "genesis";

pub struct Audit {
    path: String,
    last: Mutex<String>,
}

fn line_hash(prev: &str, body: &Map<String, Value>) -> String {
    // serde_json::Map is a BTreeMap without the preserve_order feature, so key order is stable.
    let canon = serde_json::to_string(body).unwrap_or_default();
    hex::encode(Sha256::digest(format!("{prev}{canon}").as_bytes()))
}

impl Audit {
    pub fn open(path: &str) -> Result<Audit, String> {
        let last = match verify(path) {
            Ok((_, last)) => last,
            Err(e) if e.starts_with("open") => GENESIS.to_string(),
            Err(e) => return Err(format!("audit log is broken, refusing to append: {e}")),
        };
        Ok(Audit {
            path: path.to_string(),
            last: Mutex::new(last),
        })
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn record(&self, event: Value) {
        let mut last = self.last.lock().unwrap();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut body = match event {
            Value::Object(m) => m,
            other => {
                let mut m = Map::new();
                m.insert("event".into(), other);
                m
            }
        };
        body.insert("ts".into(), json!(ts));
        body.insert("prev".into(), json!(last.clone()));
        let h = line_hash(&last, &body);
        body.insert("hash".into(), json!(h.clone()));
        let line = serde_json::to_string(&Value::Object(body)).unwrap_or_default();
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                if writeln!(f, "{line}").is_ok() {
                    *last = h;
                }
            }
            Err(e) => eprintln!("audit write failed: {e}"),
        }
    }
}

/// Returns (entries, last hash) or the first broken line.
pub fn verify(path: &str) -> Result<(usize, String), String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| format!("read line {}: {e}", i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line).map_err(|_| format!("line {} is not JSON", i + 1))?;
        let mut body = match v {
            Value::Object(m) => m,
            _ => return Err(format!("line {} is not an object", i + 1)),
        };
        let got = body
            .remove("hash")
            .and_then(|h| h.as_str().map(String::from))
            .ok_or(format!("line {} has no hash", i + 1))?;
        if body.get("prev").and_then(|p| p.as_str()) != Some(prev.as_str()) {
            return Err(format!("line {}: prev does not match the line before", i + 1));
        }
        if line_hash(&prev, &body) != got {
            return Err(format!("line {}: hash mismatch (edited)", i + 1));
        }
        prev = got;
        n += 1;
    }
    Ok((n, prev))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("sb-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn chain_verifies_and_detects_edits() {
        let p = tmp("chain");
        let a = Audit::open(&p).unwrap();
        a.record(json!({"event": "tool", "tool": "guest_list"}));
        a.record(json!({"event": "denied", "why": "token"}));
        assert_eq!(verify(&p).unwrap().0, 2);
        let edited = std::fs::read_to_string(&p).unwrap().replace("guest_list", "host_health");
        std::fs::write(&p, edited).unwrap();
        assert!(verify(&p).unwrap_err().contains("hash mismatch"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn reopen_continues_the_chain() {
        let p = tmp("reopen");
        Audit::open(&p).unwrap().record(json!({"event": "a"}));
        Audit::open(&p).unwrap().record(json!({"event": "b"}));
        assert_eq!(verify(&p).unwrap().0, 2);
        let _ = std::fs::remove_file(&p);
    }
}
