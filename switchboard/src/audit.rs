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
    raw_hash(prev, &serde_json::to_string(body).unwrap_or_default())
}

fn raw_hash(prev: &str, canon: &str) -> String {
    hex::encode(Sha256::digest(format!("{prev}{canon}").as_bytes()))
}

/// The line exactly as written, minus its `"hash":"<hash>"` member: the bytes `record` hashed. Lets `verify` check
/// the stored bytes instead of a re-serialisation (a float need not survive parse -> print unchanged).
fn written_body(line: &str, hash: &str) -> Option<String> {
    let member = format!("\"hash\":\"{hash}\"");
    let at = line.find(&member)?;
    let end = at + member.len();
    if at > 0 && line.as_bytes()[at - 1] == b',' {
        Some(format!("{}{}", &line[..at - 1], &line[end..]))
    } else if line.as_bytes().get(end) == Some(&b',') {
        Some(format!("{}{}", &line[..at], &line[end + 1..]))
    } else {
        None
    }
}

/// A crash mid-append can leave a last line with no newline. A complete entry gets its newline back; anything
/// else was never a chained entry and is cut off. Returns (bytes cut, their sha256) so `open` can record it.
fn repair_tail(path: &str) -> Result<Option<(usize, String)>, String> {
    let Ok(data) = std::fs::read(path) else { return Ok(None) };
    if data.is_empty() || data.ends_with(b"\n") {
        return Ok(None);
    }
    let start = data.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let tail = &data[start..];
    let f = OpenOptions::new().append(true).open(path).map_err(|e| format!("repair {path}: {e}"))?;
    if matches!(serde_json::from_slice::<Value>(tail), Ok(Value::Object(_))) {
        (&f).write_all(b"\n").map_err(|e| format!("repair {path}: {e}"))?;
        return Ok(None);
    }
    f.set_len(start as u64).map_err(|e| format!("repair {path}: {e}"))?;
    Ok(Some((tail.len(), hex::encode(Sha256::digest(tail)))))
}

impl Audit {
    pub fn open(path: &str) -> Result<Audit, String> {
        let cut = repair_tail(path)?;
        let last = match verify(path) {
            Ok((_, last)) => last,
            Err(e) if e.starts_with("open") => GENESIS.to_string(),
            Err(e) => return Err(format!("audit log is broken, refusing to append: {e}")),
        };
        let a = Audit {
            path: path.to_string(),
            last: Mutex::new(last),
        };
        if let Some((bytes, sha256)) = cut {
            a.record(json!({"event": "audit_torn_line_removed", "bytes": bytes, "sha256": sha256}));
        }
        Ok(a)
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
        let mut line = serde_json::to_string(&Value::Object(body)).unwrap_or_default();
        line.push('\n');
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                // One write for the line and its newline. If it fails part-way (disk full), cut the file back so
                // no torn line is left to break the chain at the next start.
                let before = f.metadata().map(|m| m.len()).ok();
                match f.write_all(line.as_bytes()) {
                    Ok(()) => *last = h,
                    Err(e) => {
                        if let Some(n) = before {
                            let _ = f.set_len(n);
                        }
                        eprintln!("audit write failed: {e}");
                    }
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
        // The written bytes first; a re-serialisation of the parsed line is still accepted, as before.
        let exact = written_body(&line, &got).map_or(false, |b| raw_hash(&prev, &b) == got);
        if !exact && line_hash(&prev, &body) != got {
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
    fn verify_checks_the_written_bytes_not_a_reserialisation() {
        // `1E2` parses to 100.0, which prints as `100.0`: hashing a re-serialisation could never match this line.
        let p = tmp("bytes");
        let body = r#"{"event":"tool","n":1E2,"prev":"genesis","ts":1}"#;
        let h = raw_hash(GENESIS, body);
        std::fs::write(&p, format!("{{\"event\":\"tool\",\"hash\":\"{h}\",\"n\":1E2,\"prev\":\"genesis\",\"ts\":1}}\n")).unwrap();
        assert_eq!(verify(&p).unwrap(), (1, h.clone()));
        let edited = std::fs::read_to_string(&p).unwrap().replace("1E2", "2E2");
        std::fs::write(&p, edited).unwrap();
        assert!(verify(&p).unwrap_err().contains("hash mismatch"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_torn_last_line_is_cut_and_recorded_not_fatal() {
        let p = tmp("torn");
        Audit::open(&p).unwrap().record(json!({"event": "a"}));
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(br#"{"event":"torn-marker","pr"#).unwrap();
        assert!(verify(&p).is_err());
        let a = Audit::open(&p).unwrap();
        a.record(json!({"event": "c"}));
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(verify(&p).unwrap().0, 3);
        assert!(text.contains("audit_torn_line_removed") && !text.contains("torn-marker"));
        // A complete last entry that only lost its newline is kept.
        let q = tmp("torn-nl");
        Audit::open(&q).unwrap().record(json!({"event": "a"}));
        let t = std::fs::read_to_string(&q).unwrap();
        std::fs::write(&q, t.trim_end()).unwrap();
        Audit::open(&q).unwrap().record(json!({"event": "b"}));
        assert_eq!(verify(&q).unwrap().0, 2);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&q);
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
