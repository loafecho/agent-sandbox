//! The guard ladder. Every request passes these in order; each returns a Deny on failure.
//! The RED_* constants exist only for prove-red.sh, which flips one to `true` in a scratch copy and
//! requires the test suite to fail. They are `false` here and nothing else reads them.

use crate::config::Config;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const RED_SOURCE: bool = false;
const RED_TOKEN: bool = false;
const RED_TOOLS: bool = false;
const RED_ARGS: bool = false;
const RED_RATE: bool = false;
const RED_APPROVER: bool = false;
const RED_ALLOWLIST: bool = false;
const RED_CLAIMONCE: bool = false;
const RED_UV: bool = false;
const RED_RPID: bool = false;
const RED_ORIGIN: bool = false;
const RED_CHALLENGE: bool = false;
const RED_SIGNCOUNT: bool = false;
const RED_SIGNATURE: bool = false;
const RED_ENROLL: bool = false;
const RED_BACKEND: bool = false;
const RED_DEVICE: bool = false;

#[derive(Debug, PartialEq)]
pub struct Deny {
    pub code: u16,
    pub why: String,
}

fn deny(code: u16, why: impl Into<String>) -> Deny {
    Deny { code, why: why.into() }
}

/// 1. Only the listed source IPs (agent-host) may talk to the switchboard at all.
pub fn source(cfg: &Config, ip: &str) -> Result<(), Deny> {
    if RED_SOURCE {
        return Ok(());
    }
    if cfg.allowed_sources.iter().any(|s| s == ip) {
        Ok(())
    } else {
        Err(deny(403, "source"))
    }
}

/// 2. Bearer token, compared by sha256 in constant time. Returns the agent it belongs to.
pub fn token(cfg: &Config, header: Option<&str>) -> Result<String, Deny> {
    if RED_TOKEN {
        return Ok(cfg.agents.keys().next().cloned().unwrap_or_default());
    }
    let h = header.unwrap_or("");
    let tok = match h.get(..7) {
        Some(p) if p.eq_ignore_ascii_case("bearer ") => h[7..].trim(),
        _ => return Err(deny(401, "token")),
    };
    if tok.is_empty() {
        return Err(deny(401, "token"));
    }
    let got = hex::encode(Sha256::digest(tok.as_bytes()));
    let mut found = None;
    for (name, a) in &cfg.agents {
        if bool::from(got.as_bytes().ct_eq(a.token_sha256.as_bytes())) {
            found = Some(name.clone());
        }
    }
    found.ok_or_else(|| deny(401, "token"))
}

/// 3. The agent may call only the tools listed for it.
pub fn tool_allowed(cfg: &Config, agent: &str, tool: &str) -> Result<(), Deny> {
    if RED_TOOLS {
        return Ok(());
    }
    match cfg.agents.get(agent) {
        Some(a) if a.tools.iter().any(|t| t == tool) => Ok(()),
        _ => Err(deny(403, format!("tool {tool} is not allowed for {agent}"))),
    }
}

/// 4. Arguments: an object, no unknown keys, every value a string matching its declared pattern.
pub fn args(cfg: &Config, tool: &str, args: &Value) -> Result<(), Deny> {
    if RED_ARGS {
        return Ok(());
    }
    let spec = cfg.tools.get(tool).ok_or_else(|| deny(400, format!("unknown tool {tool}")))?;
    let obj = match args {
        Value::Object(m) => m,
        Value::Null => &serde_json::Map::new(),
        _ => return Err(deny(400, "arguments must be an object")),
    };
    for k in obj.keys() {
        if !spec.args.contains_key(k) {
            return Err(deny(400, format!("unknown argument {k}")));
        }
    }
    for (name, a) in &spec.args {
        match obj.get(name) {
            None if a.required => return Err(deny(400, format!("missing argument {name}"))),
            None => {}
            Some(Value::String(s)) => {
                let pat = a.pattern.as_deref().unwrap_or("^$");
                let re = Regex::new(pat).map_err(|_| deny(500, "bad pattern in config"))?;
                if s.len() > 256 || !re.is_match(s) {
                    return Err(deny(400, format!("argument {name} does not match {pat}")));
                }
            }
            Some(_) => return Err(deny(400, format!("argument {name} must be a string"))),
        }
    }
    Ok(())
}

/// 4b. Forwarded tools: the arguments must be a JSON object of bounded size; the upstream gateway
/// validates them against its own schema (it always has).
pub fn forward_args(args: &Value) -> Result<(), Deny> {
    match args {
        Value::Object(_) | Value::Null if args.to_string().len() <= 8 * 1024 => Ok(()),
        Value::Object(_) | Value::Null => Err(deny(400, "arguments over 8 KiB")),
        _ => Err(deny(400, "arguments must be an object")),
    }
}

/// 5. Per-agent rate limit over a rolling minute.
pub struct RateLimiter {
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            calls: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, cfg: &Config, agent: &str) -> Result<(), Deny> {
        if RED_RATE {
            return Ok(());
        }
        let limit = cfg.agents.get(agent).map(|a| a.rate_per_min).unwrap_or(0) as usize;
        let now = Instant::now();
        let mut map = self.calls.lock().unwrap();
        let q = map.entry(agent.to_string()).or_default();
        while q.front().map_or(false, |t| now.duration_since(*t) > Duration::from_secs(60)) {
            q.pop_front();
        }
        if q.len() >= limit {
            return Err(deny(429, format!("rate limit {limit}/min for {agent}")));
        }
        q.push_back(now);
        Ok(())
    }
}

/// 6. Approve tier: only the approver's own reaction counts. Every other user (the bot's own ✅
/// included) is ignored.
pub fn approver_reacted(approver: &str, users: &[String]) -> bool {
    if RED_APPROVER {
        return !users.is_empty();
    }
    !approver.is_empty() && users.iter().any(|u| u == approver)
}

/// 7. Power actions: only guests on the allowlist (sbsecrets.py POWER_VMIDS, via gen.py). Checked
/// before anything is posted to Discord.
pub fn power_allowed(allowlist: &[String], vmid: &str) -> Result<(), Deny> {
    if RED_ALLOWLIST {
        return Ok(());
    }
    if allowlist.iter().any(|v| v == vmid) {
        Ok(())
    } else {
        Err(deny(403, format!("vmid {vmid} is not on the power allowlist")))
    }
}

/// 8. A request is decided once. Only a still-pending request inside its window can be claimed, so a
/// Discord ✅ and a passkey approve on the same request run the write once (approve.rs `claim`).
pub fn claimable(status: &str, created: u64, window: u64, now: u64) -> bool {
    if RED_CLAIMONCE {
        return true;
    }
    status == "pending" && now < created + window
}

/// 9. WebAuthn: the authenticator must report user presence AND user verification (biometric or PIN),
/// flags bits 0 (UP) and 2 (UV).
pub fn wa_user_verified(flags: u8) -> Result<(), Deny> {
    if RED_UV {
        return Ok(());
    }
    if flags & 0x01 != 0 && flags & 0x04 != 0 {
        Ok(())
    } else {
        Err(deny(403, "webauthn: user not verified"))
    }
}

/// 10. WebAuthn: authenticatorData starts with sha256(rpId); a credential made for any other site fails.
pub fn wa_rp_id(rp_id: &str, auth_data: &[u8]) -> Result<(), Deny> {
    if RED_RPID {
        return Ok(());
    }
    let want = Sha256::digest(rp_id.as_bytes());
    match auth_data.get(..32) {
        Some(h) if bool::from(h.ct_eq(want.as_slice())) => Ok(()),
        _ => Err(deny(403, "webauthn: wrong rpId")),
    }
}

/// 11. WebAuthn: clientDataJSON.origin is exactly the approval page's origin.
pub fn wa_origin(want: &str, got: &str) -> Result<(), Deny> {
    if RED_ORIGIN {
        return Ok(());
    }
    if !want.is_empty() && want == got {
        Ok(())
    } else {
        Err(deny(403, "webauthn: wrong origin"))
    }
}

/// What a challenge was issued for. A challenge works once, for 120 s, for exactly this purpose.
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub purpose: String,
    pub expires: u64,
}

/// 12. WebAuthn: the challenge in clientDataJSON was issued by us, is unexpired, and was issued for
/// this purpose (request id + decision + args sha256, or this enrollment code). `issued` is what the
/// store handed back when the challenge was taken (None = unknown or already used).
pub fn wa_challenge(issued: Option<&Binding>, purpose: &str, now: u64) -> Result<(), Deny> {
    if RED_CHALLENGE {
        return Ok(());
    }
    match issued {
        Some(b) if b.purpose == purpose && now <= b.expires => Ok(()),
        Some(b) if b.purpose != purpose => Err(deny(403, "webauthn: challenge was issued for something else")),
        Some(_) => Err(deny(403, "webauthn: challenge expired")),
        None => Err(deny(403, "webauthn: unknown or reused challenge")),
    }
}

/// 13. WebAuthn: the signature counter never goes backwards. 0 -> 0 is allowed (iCloud passkeys
/// always report 0); otherwise the new count must be higher than the stored one.
pub fn wa_sign_count(stored: u32, got: u32) -> Result<(), Deny> {
    if RED_SIGNCOUNT {
        return Ok(());
    }
    if (stored == 0 && got == 0) || got > stored {
        Ok(())
    } else {
        Err(deny(403, "webauthn: signature counter went backwards (cloned authenticator?)"))
    }
}

/// 14. WebAuthn: ES256 signature over authenticatorData || sha256(clientDataJSON), by the enrolled key.
pub fn wa_signature(x: &[u8], y: &[u8], auth_data: &[u8], client_data: &[u8], sig_der: &[u8]) -> Result<(), Deny> {
    if RED_SIGNATURE {
        return Ok(());
    }
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let bad = || deny(403, "webauthn: bad signature");
    if x.len() != 32 || y.len() != 32 {
        return Err(bad());
    }
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| bad())?;
    let sig = Signature::from_der(sig_der).map_err(|_| bad())?;
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data));
    key.verify(&msg, &sig).map_err(|_| bad())
}

/// 15. Enrollment needs a one-time code made by root (`switchboard enroll-code`): its sha256 must
/// match an unused, unexpired code.
pub fn enroll_code(code: &str, stored_sha256: &str, expires: u64, used: bool, now: u64) -> Result<(), Deny> {
    if RED_ENROLL {
        return Ok(());
    }
    let got = hex::encode(Sha256::digest(code.trim().as_bytes()));
    if !code.trim().is_empty() && !used && now <= expires && bool::from(got.as_bytes().ct_eq(stored_sha256.as_bytes())) {
        Ok(())
    } else {
        Err(deny(403, "enroll: bad, used or expired code"))
    }
}

/// 16. Forwarded tools: an agent reaches only the upstream backend its own config maps that tool's
/// group to (media-eval -> the eval fixture only, never the real pipeline). Returns the backend name.
pub fn backend(cfg: &Config, agent: &str, tool: &str) -> Result<String, Deny> {
    let group = cfg
        .tools
        .get(tool)
        .and_then(|t| t.upstream.clone())
        .ok_or_else(|| deny(400, format!("{tool} is not a forwarded tool")))?;
    if RED_BACKEND {
        return Ok(group);
    }
    let be = cfg
        .agents
        .get(agent)
        .and_then(|a| a.forward.get(&group).cloned())
        .ok_or_else(|| deny(403, format!("{agent} has no backend for {group}")))?;
    if cfg.backends.get(&be).map(|b| b.group == group).unwrap_or(false) {
        Ok(be)
    } else {
        Err(deny(403, format!("backend {be} is not a {group} backend")))
    }
}

/// 17. The passkey page answers only the approver's phone. `tailscale serve` handles 443 inside tailscaled (the VM
/// firewall never sees it) and replaces X-Forwarded-For with the caller's real tailnet address (a client's own
/// header is dropped: verified 2026-10-20 from workstation). The listener is on 127.0.0.1 only, so `xff` is exactly
/// what tailscaled saw; a missing header means a local caller, which falls back to the socket address.
pub fn web_device(allow: &[String], xff: Option<&str>, peer: &str) -> Result<(), Deny> {
    if RED_DEVICE {
        return Ok(());
    }
    let who = match xff {
        Some(v) if !v.contains(',') => v.trim(),
        Some(_) => return Err(deny(403, "device: more than one forwarded address")),
        None => peer,
    };
    if !who.is_empty() && allow.iter().any(|a| a == who) {
        Ok(())
    } else {
        Err(deny(403, "device: this page answers only the approver's phone"))
    }
}
