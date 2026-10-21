//! WebAuthn (passkeys) for the approval page, by hand: ES256 only, attestation "none",
//! user verification required. Every check that can refuse is a guard in guards.rs (RED_UV, RED_RPID,
//! RED_ORIGIN, RED_CHALLENGE, RED_SIGNCOUNT, RED_SIGNATURE, RED_ENROLL); this file only parses.
//!
//!   enrollment  `switchboard enroll-code` (root) writes the sha256 of a one-time code (15 min, one
//!               credential). The page sends the code, gets a challenge, the phone makes a passkey.
//!   assertion   each Approve/Deny tap gets its own challenge: 32 random bytes, 120 s, single use, bound
//!               to the request id, the decision and the sha256 of the request's arguments.

use crate::guards::{self, Binding, Deny};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

pub const CHALLENGE_SECS: u64 = 120;
pub const ENROLL_SECS: u64 = 900;
pub const MAX_CREDENTIALS: usize = 4;

pub fn b64e(b: &[u8]) -> String {
    B64.encode(b)
}

pub fn b64d(s: &str) -> Result<Vec<u8>, Deny> {
    B64.decode(s.trim_end_matches('=')).map_err(|_| Deny {
        code: 400,
        why: "webauthn: bad base64url".into(),
    })
}

fn bad(why: &str) -> Deny {
    Deny {
        code: 400,
        why: format!("webauthn: {why}"),
    }
}

pub fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("os randomness");
    b
}

// ------------------------------------------------------------------------------------------ CBOR

/// Just enough CBOR for attestationObject and a COSE EC2 key.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Decode one item; returns it and the bytes used. Depth and lengths are bounded.
pub fn cbor(b: &[u8]) -> Result<(Cbor, usize), Deny> {
    fn item(b: &[u8], at: &mut usize, depth: u32) -> Result<Cbor, Deny> {
        if depth > 8 {
            return Err(bad("cbor too deep"));
        }
        let ib = *b.get(*at).ok_or_else(|| bad("cbor truncated"))?;
        *at += 1;
        let (major, info) = (ib >> 5, ib & 0x1f);
        let mut arg = |info: u8| -> Result<u64, Deny> {
            let n = match info {
                0..=23 => return Ok(info as u64),
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(bad("cbor indefinite length")),
            };
            let s = b.get(*at..*at + n).ok_or_else(|| bad("cbor truncated"))?;
            *at += n;
            Ok(s.iter().fold(0u64, |a, x| (a << 8) | *x as u64))
        };
        match major {
            0 => Ok(Cbor::Int(i64::try_from(arg(info)?).map_err(|_| bad("cbor int"))?)),
            1 => Ok(Cbor::Int(-1 - i64::try_from(arg(info)?).map_err(|_| bad("cbor int"))?)),
            2 | 3 => {
                let n = arg(info)? as usize;
                if n > 64 * 1024 {
                    return Err(bad("cbor string too long"));
                }
                let s = b.get(*at..*at + n).ok_or_else(|| bad("cbor truncated"))?.to_vec();
                *at += n;
                if major == 2 {
                    Ok(Cbor::Bytes(s))
                } else {
                    String::from_utf8(s).map(Cbor::Text).map_err(|_| bad("cbor text"))
                }
            }
            4 => {
                let n = arg(info)? as usize;
                if n > 64 {
                    return Err(bad("cbor array too long"));
                }
                (0..n).map(|_| item(b, at, depth + 1)).collect::<Result<_, _>>().map(Cbor::Array)
            }
            5 => {
                let n = arg(info)? as usize;
                if n > 64 {
                    return Err(bad("cbor map too long"));
                }
                let mut m = Vec::new();
                for _ in 0..n {
                    let k = item(b, at, depth + 1)?;
                    let v = item(b, at, depth + 1)?;
                    m.push((k, v));
                }
                Ok(Cbor::Map(m))
            }
            7 => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(bad("cbor simple value")),
            },
            _ => Err(bad("cbor tag")),
        }
    }
    let mut at = 0;
    let v = item(b, &mut at, 0)?;
    Ok((v, at))
}

// ------------------------------------------------------------------------------------- authData

#[derive(Debug, Clone)]
pub struct AuthData {
    pub flags: u8,
    pub sign_count: u32,
    /// Present when the AT flag is set (registration): credential id and the P-256 x, y.
    pub cred: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

pub fn auth_data(d: &[u8]) -> Result<AuthData, Deny> {
    if d.len() < 37 {
        return Err(bad("authenticatorData too short"));
    }
    let flags = d[32];
    let sign_count = u32::from_be_bytes([d[33], d[34], d[35], d[36]]);
    let mut cred = None;
    if flags & 0x40 != 0 {
        let rest = &d[37..];
        if rest.len() < 18 {
            return Err(bad("attested credential data too short"));
        }
        let n = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        if n == 0 || n > 1023 || rest.len() < 18 + n {
            return Err(bad("credential id length"));
        }
        let id = rest[18..18 + n].to_vec();
        let (key, _) = cbor(&rest[18 + n..])?;
        let kty = key.get(&Cbor::Int(1));
        let alg = key.get(&Cbor::Int(3));
        let crv = key.get(&Cbor::Int(-1));
        if kty != Some(&Cbor::Int(2)) || alg != Some(&Cbor::Int(-7)) || crv != Some(&Cbor::Int(1)) {
            return Err(bad("only ES256 (P-256) keys"));
        }
        let (x, y) = match (key.get(&Cbor::Int(-2)), key.get(&Cbor::Int(-3))) {
            (Some(Cbor::Bytes(x)), Some(Cbor::Bytes(y))) if x.len() == 32 && y.len() == 32 => (x.clone(), y.clone()),
            _ => return Err(bad("bad EC2 key")),
        };
        cred = Some((id, x, y));
    }
    Ok(AuthData { flags, sign_count, cred })
}

// ---------------------------------------------------------------------------------- client data

pub struct ClientData {
    pub ty: String,
    pub challenge: String,
    pub origin: String,
}

pub fn client_data(raw: &[u8]) -> Result<ClientData, Deny> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| bad("clientDataJSON is not JSON"))?;
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    if v["crossOrigin"].as_bool() == Some(true) {
        return Err(bad("cross-origin"));
    }
    Ok(ClientData {
        ty: s("type"),
        challenge: s("challenge"),
        origin: s("origin"),
    })
}

// ------------------------------------------------------------------------------------ challenges

/// Issued challenges, keyed by their base64url. Taking one removes it: a challenge works once.
pub struct Challenges {
    map: Mutex<HashMap<String, Binding>>,
}

impl Challenges {
    pub fn new() -> Self {
        Challenges {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, purpose: &str, now: u64) -> String {
        let c = b64e(&random(32));
        let mut m = self.map.lock().unwrap();
        m.retain(|_, b| b.expires >= now);
        if m.len() > 256 {
            m.clear(); // a flood never grows the map without bound
        }
        m.insert(
            c.clone(),
            Binding {
                purpose: purpose.into(),
                expires: now + CHALLENGE_SECS,
            },
        );
        c
    }

    pub fn take(&self, c: &str) -> Option<Binding> {
        self.map.lock().unwrap().remove(c)
    }
}

/// "assert:<request>:<approve|deny>:<args sha256>" or "enroll:<code sha256>".
pub fn assert_purpose(request: &str, decision: &str, args_sha256: &str) -> String {
    format!("assert:{request}:{decision}:{args_sha256}")
}

// ----------------------------------------------------------------------------------- credentials

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credential {
    pub id: String,
    pub x: String,
    pub y: String,
    pub sign_count: u32,
    pub created: u64,
}

/// The enrolled passkeys, in `credentials_file` (switchboard-owned, 0600).
pub struct Credentials {
    path: String,
    list: Mutex<Vec<Credential>>,
}

impl Credentials {
    pub fn open(path: &str) -> Credentials {
        let list = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Credentials {
            path: path.into(),
            list: Mutex::new(list),
        }
    }

    pub fn count(&self) -> usize {
        self.list.lock().unwrap().len()
    }

    pub fn ids(&self) -> Vec<String> {
        self.list.lock().unwrap().iter().map(|c| c.id.clone()).collect()
    }

    fn save(&self, list: &[Credential]) -> Result<(), String> {
        let tmp = tmp_name(&self.path);
        let body = serde_json::to_string_pretty(list).unwrap_or_default();
        write_private(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string()))
    }

    pub fn add(&self, c: Credential) -> Result<(), String> {
        let mut list = self.list.lock().unwrap();
        if list.len() >= MAX_CREDENTIALS {
            return Err(format!("already {MAX_CREDENTIALS} credentials enrolled"));
        }
        if list.iter().any(|x| x.id == c.id) {
            return Err("credential already enrolled".into());
        }
        list.push(c);
        self.save(&list)
    }

    /// Verify one assertion against the enrolled credential it names, and move its counter on.
    pub fn verify(
        &self,
        rp_id: &str,
        origin: &str,
        cred_id: &str,
        cd_raw: &[u8],
        ad_raw: &[u8],
        sig: &[u8],
        issued: Option<&Binding>,
        purpose: &str,
        now: u64,
    ) -> Result<(), Deny> {
        let cd = client_data(cd_raw)?;
        if cd.ty != "webauthn.get" {
            return Err(bad("clientData type is not webauthn.get"));
        }
        guards::wa_challenge(issued, purpose, now)?;
        guards::wa_origin(origin, &cd.origin)?;
        guards::wa_rp_id(rp_id, ad_raw)?;
        let ad = auth_data(ad_raw)?;
        guards::wa_user_verified(ad.flags)?;
        let mut list = self.list.lock().unwrap();
        let c = list.iter_mut().find(|c| c.id == cred_id).ok_or(Deny {
            code: 403,
            why: "webauthn: unknown credential".into(),
        })?;
        guards::wa_signature(&b64d(&c.x)?, &b64d(&c.y)?, ad_raw, cd_raw, sig)?;
        guards::wa_sign_count(c.sign_count, ad.sign_count)?;
        c.sign_count = ad.sign_count;
        // Saved while the lock is held, so concurrent saves can neither collide nor land out of order (RACE-4).
        self.save(&list).map_err(|e| Deny { code: 500, why: e })
    }
}

/// Check a registration (navigator.credentials.create) and return the new credential.
pub fn verify_registration(
    rp_id: &str,
    origin: &str,
    cd_raw: &[u8],
    att_raw: &[u8],
    issued: Option<&Binding>,
    purpose: &str,
    now: u64,
) -> Result<Credential, Deny> {
    let cd = client_data(cd_raw)?;
    if cd.ty != "webauthn.create" {
        return Err(bad("clientData type is not webauthn.create"));
    }
    guards::wa_challenge(issued, purpose, now)?;
    guards::wa_origin(origin, &cd.origin)?;
    let (att, _) = cbor(att_raw)?;
    if att.get(&Cbor::Text("fmt".into())) != Some(&Cbor::Text("none".into())) {
        return Err(bad("only attestation \"none\""));
    }
    let ad_raw = match att.get(&Cbor::Text("authData".into())) {
        Some(Cbor::Bytes(b)) => b.clone(),
        _ => return Err(bad("no authData")),
    };
    guards::wa_rp_id(rp_id, &ad_raw)?;
    let ad = auth_data(&ad_raw)?;
    guards::wa_user_verified(ad.flags)?;
    let (id, x, y) = ad.cred.ok_or_else(|| bad("no attested credential"))?;
    Ok(Credential {
        id: b64e(&id),
        x: b64e(&x),
        y: b64e(&y),
        sign_count: ad.sign_count,
        created: now,
    })
}

// --------------------------------------------------------------------------------- enroll codes

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrollCode {
    pub sha256: String,
    pub expires: u64,
    pub used: bool,
}

/// Write a fresh one-time code (replacing any earlier one) and return it. Only `switchboard
/// enroll-code` calls this, and a production build runs that only as root.
#[allow(dead_code)] // tests and staging
pub fn new_enroll_code(path: &str, now: u64) -> Result<String, String> {
    new_enroll_code_for(path, now, None)
}

/// Production: the code file lives in root's /etc/switchboard, mode 0640 group switchboard, set on the open
/// file (fchown) before it is renamed into place, so nothing is ever changed by path (SEC-1, round 2). The
/// service only reads it; it records a used code in its own file (`used_file`).
pub fn new_enroll_code_for(path: &str, now: u64, group: Option<u32>) -> Result<String, String> {
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let code: String = random(12).iter().map(|b| ALPHA[*b as usize % ALPHA.len()] as char).collect();
    let rec = EnrollCode {
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(code.as_bytes())),
        expires: now + ENROLL_SECS,
        used: false,
    };
    let tmp = tmp_name(path);
    let f = write_file(
        &tmp,
        &serde_json::to_string(&rec).unwrap_or_default(),
        if group.is_some() { 0o640 } else { 0o600 },
    )?;
    if let Some(g) = group {
        std::os::unix::fs::fchown(&f, Some(0), Some(g)).map_err(|e| format!("fchown {tmp}: {e}"))?;
    }
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(code)
}

/// The service's own record of used codes (sha256 per line), next to the credentials.
pub fn used_file(credentials_file: &str) -> String {
    format!("{credentials_file}.enroll-used")
}

pub fn code_used(used_path: &str, sha: &str) -> bool {
    std::fs::read_to_string(used_path).map(|s| s.lines().any(|l| l.trim() == sha)).unwrap_or(false)
}

pub fn load_enroll_code(path: &str) -> Option<EnrollCode> {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok())
}

#[allow(dead_code)] // tests: the v0.4.0 in-file used flag still refuses
pub fn mark_enroll_code_used(path: &str, rec: &EnrollCode) -> Result<(), String> {
    let mut r = rec.clone();
    r.used = true;
    let tmp = tmp_name(path);
    write_private(&tmp, &serde_json::to_string(&r).unwrap_or_default())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Append a used code's sha256 to the service's own record (0600).
pub fn record_code_used(used_path: &str, sha: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(used_path)
        .map_err(|e| format!("write {used_path}: {e}"))?;
    writeln!(f, "{sha}").map_err(|e| format!("write {used_path}: {e}"))
}

/// A temp name no other writer uses (RACE-4): pid, thread and a random suffix.
fn tmp_name(path: &str) -> String {
    format!("{path}.tmp-{}-{}", std::process::id(), b64e(&random(6)))
}

fn write_private(path: &str, body: &str) -> Result<(), String> {
    write_file(path, body, 0o600).map(|_| ())
}

fn write_file(path: &str, body: &str, mode: u32) -> Result<std::fs::File, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("write {path}: {e}"))?;
    f.write_all(body.as_bytes()).map_err(|e| format!("write {path}: {e}"))?;
    Ok(f)
}

#[cfg(test)]
pub mod soft {
    //! A software authenticator for tests: a P-256 key that signs like a phone would.
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};

    pub struct Soft {
        pub key: SigningKey,
        pub id: Vec<u8>,
        pub count: u32,
        pub rp_id: String,
        pub origin: String,
    }

    fn enc_bytes(major: u8, b: &[u8]) -> Vec<u8> {
        let mut v = vec![(major << 5) | 24, b.len() as u8];
        v.extend_from_slice(b);
        v
    }

    impl Soft {
        pub fn new(rp_id: &str, origin: &str) -> Soft {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            Soft {
                key: SigningKey::from_slice(&seed).unwrap(),
                id: random(16),
                count: 0,
                rp_id: rp_id.into(),
                origin: origin.into(),
            }
        }

        pub fn client_data(&self, ty: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::json!({"type": ty, "challenge": challenge, "origin": origin, "crossOrigin": false})
                .to_string()
                .into_bytes()
        }

        pub fn auth_data(&self, rp_id: &str, flags: u8, count: u32, with_cred: bool) -> Vec<u8> {
            let mut d = Sha256::digest(rp_id.as_bytes()).to_vec();
            d.push(flags | if with_cred { 0x40 } else { 0 });
            d.extend_from_slice(&count.to_be_bytes());
            if with_cred {
                d.extend_from_slice(&[0u8; 16]);
                d.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
                d.extend_from_slice(&self.id);
                let p = self.key.verifying_key().to_encoded_point(false);
                let mut k = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01];
                k.push(0x21);
                k.extend(enc_bytes(2, p.x().unwrap()));
                k.push(0x22);
                k.extend(enc_bytes(2, p.y().unwrap()));
                d.extend(k);
            }
            d
        }

        /// attestationObject {fmt: "none", attStmt: {}, authData}.
        pub fn attestation(&self, auth_data: &[u8]) -> Vec<u8> {
            let mut a = vec![0xa3];
            a.extend(enc_bytes(3, b"fmt"));
            a.extend(enc_bytes(3, b"none"));
            a.extend(enc_bytes(3, b"attStmt"));
            a.push(0xa0);
            a.extend(enc_bytes(3, b"authData"));
            a.push(0x59);
            a.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
            a.extend_from_slice(auth_data);
            a
        }

        pub fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
            let mut m = auth_data.to_vec();
            m.extend_from_slice(&Sha256::digest(client_data));
            let s: Signature = self.key.sign(&m);
            s.to_der().as_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::Soft;
    use super::*;

    const RP: &str = "switchboard.tailnet.example";
    const ORIGIN: &str = "https://switchboard.tailnet.example";

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("sb-wa-{name}-{}-{}", std::process::id(), b64e(&random(4))));
        p.to_string_lossy().into_owned()
    }

    /// Enroll a soft authenticator through verify_registration; returns (store, authenticator).
    fn enrolled() -> (Credentials, Soft, Challenges) {
        let ch = Challenges::new();
        let soft = Soft::new(RP, ORIGIN);
        let c = ch.issue("enroll:x", 1000);
        let cd = soft.client_data("webauthn.create", &c, ORIGIN);
        let att = soft.attestation(&soft.auth_data(RP, 0x05, 0, true));
        let cred = verify_registration(RP, ORIGIN, &cd, &att, ch.take(&c).as_ref(), "enroll:x", 1001).unwrap();
        let store = Credentials::open(&tmp("creds"));
        store.add(cred).unwrap();
        (store, soft, ch)
    }

    struct Try {
        ty: &'static str,
        rp: &'static str,
        origin: &'static str,
        flags: u8,
        count: u32,
        purpose: &'static str,
        forge: bool,
    }

    const OK: Try = Try {
        ty: "webauthn.get",
        rp: RP,
        origin: ORIGIN,
        flags: 0x05,
        count: 0,
        purpose: "assert:r-1:approve:abc",
        forge: false,
    };

    fn attempt(store: &Credentials, soft: &Soft, ch: &Challenges, t: Try) -> Result<(), Deny> {
        let c = ch.issue("assert:r-1:approve:abc", 2000);
        let cd = soft.client_data(t.ty, &c, t.origin);
        let ad = soft.auth_data(t.rp, t.flags, t.count, false);
        let mut sig = soft.sign(&ad, &cd);
        if t.forge {
            sig = Soft::new(RP, ORIGIN).sign(&ad, &cd); // a different key
        }
        store.verify(RP, ORIGIN, &b64e(&soft.id), &cd, &ad, &sig, ch.take(&c).as_ref(), t.purpose, 2001)
    }

    #[test]
    fn good_assertion_passes() {
        let (store, soft, ch) = enrolled();
        attempt(&store, &soft, &ch, OK).unwrap();
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn forged_signature_is_refused() {
        let (store, soft, ch) = enrolled();
        let e = attempt(&store, &soft, &ch, Try { forge: true, ..OK }).unwrap_err();
        assert!(e.why.contains("signature"), "{e:?}");
    }

    #[test]
    fn wrong_rp_id_is_refused() {
        let (store, soft, ch) = enrolled();
        let e = attempt(&store, &soft, &ch, Try { rp: "evil.example", ..OK }).unwrap_err();
        assert!(e.why.contains("rpId"), "{e:?}");
    }

    #[test]
    fn no_user_verification_is_refused() {
        let (store, soft, ch) = enrolled();
        let e = attempt(&store, &soft, &ch, Try { flags: 0x01, ..OK }).unwrap_err();
        assert!(e.why.contains("not verified"), "{e:?}");
        let e = attempt(&store, &soft, &ch, Try { flags: 0x04, ..OK }).unwrap_err();
        assert!(e.why.contains("not verified"), "{e:?}");
    }

    #[test]
    fn wrong_origin_is_refused() {
        let (store, soft, ch) = enrolled();
        for o in [
            "https://evil.example",
            "http://switchboard.tailnet.example",
            "https://switchboard.tailnet.example.evil",
            "",
        ] {
            let e = attempt(
                &store,
                &soft,
                &ch,
                Try {
                    origin: Box::leak(o.to_string().into_boxed_str()),
                    ..OK
                },
            )
            .unwrap_err();
            assert!(e.why.contains("origin"), "{o}: {e:?}");
        }
    }

    #[test]
    fn replayed_unknown_and_foreign_challenges_are_refused() {
        let (store, soft, ch) = enrolled();
        // replay: the same signed assertion twice
        let c = ch.issue("assert:r-1:approve:abc", 2000);
        let cd = soft.client_data("webauthn.get", &c, ORIGIN);
        let ad = soft.auth_data(RP, 0x05, 0, false);
        let sig = soft.sign(&ad, &cd);
        let id = b64e(&soft.id);
        store
            .verify(RP, ORIGIN, &id, &cd, &ad, &sig, ch.take(&c).as_ref(), "assert:r-1:approve:abc", 2001)
            .unwrap();
        let e = store
            .verify(RP, ORIGIN, &id, &cd, &ad, &sig, ch.take(&c).as_ref(), "assert:r-1:approve:abc", 2002)
            .unwrap_err();
        assert!(e.why.contains("reused"), "{e:?}");
        // never issued
        let made_up = b64e(&random(32));
        let cd = soft.client_data("webauthn.get", &made_up, ORIGIN);
        let sig = soft.sign(&ad, &cd);
        assert!(store
            .verify(RP, ORIGIN, &id, &cd, &ad, &sig, ch.take(&made_up).as_ref(), "assert:r-1:approve:abc", 2003)
            .is_err());
        // foreign: issued for another request, for deny instead of approve, or for other arguments
        for other in ["assert:r-2:approve:abc", "assert:r-1:deny:abc", "assert:r-1:approve:def"] {
            let e = attempt(
                &store,
                &soft,
                &ch,
                Try {
                    purpose: Box::leak(other.to_string().into_boxed_str()),
                    ..OK
                },
            )
            .unwrap_err();
            assert!(e.why.contains("something else"), "{other}: {e:?}");
        }
        // expired
        let c = ch.issue("assert:r-1:approve:abc", 2000);
        let cd = soft.client_data("webauthn.get", &c, ORIGIN);
        let sig = soft.sign(&ad, &cd);
        let e = store
            .verify(
                RP,
                ORIGIN,
                &id,
                &cd,
                &ad,
                &sig,
                ch.take(&c).as_ref(),
                "assert:r-1:approve:abc",
                2000 + CHALLENGE_SECS + 1,
            )
            .unwrap_err();
        assert!(e.why.contains("expired"), "{e:?}");
    }

    #[test]
    fn lower_or_equal_sign_count_is_refused() {
        let (store, soft, ch) = enrolled();
        attempt(&store, &soft, &ch, Try { count: 5, ..OK }).unwrap();
        let e = attempt(&store, &soft, &ch, Try { count: 4, ..OK }).unwrap_err();
        assert!(e.why.contains("backwards"), "{e:?}");
        assert!(attempt(&store, &soft, &ch, Try { count: 5, ..OK }).is_err());
        attempt(&store, &soft, &ch, Try { count: 6, ..OK }).unwrap();
    }

    #[test]
    fn zero_sign_count_stays_allowed() {
        let (store, soft, ch) = enrolled();
        for _ in 0..3 {
            attempt(&store, &soft, &ch, OK).unwrap();
        }
    }

    #[test]
    fn create_type_is_not_an_assertion() {
        let (store, soft, ch) = enrolled();
        assert!(attempt(&store, &soft, &ch, Try { ty: "webauthn.create", ..OK }).is_err());
    }

    #[test]
    fn registration_checks_uv_rp_origin_and_challenge() {
        let soft = Soft::new(RP, ORIGIN);
        let ch = Challenges::new();
        let reg = |rp: &str, flags: u8, origin: &str, purpose: &str| {
            let c = ch.issue("enroll:x", 1000);
            let cd = soft.client_data("webauthn.create", &c, origin);
            let att = soft.attestation(&soft.auth_data(rp, flags, 0, true));
            verify_registration(RP, ORIGIN, &cd, &att, ch.take(&c).as_ref(), purpose, 1001)
        };
        assert!(reg(RP, 0x05, ORIGIN, "enroll:x").is_ok());
        assert!(reg(RP, 0x01, ORIGIN, "enroll:x").unwrap_err().why.contains("not verified"));
        assert!(reg("evil.example", 0x05, ORIGIN, "enroll:x").unwrap_err().why.contains("rpId"));
        assert!(reg(RP, 0x05, "https://evil.example", "enroll:x").unwrap_err().why.contains("origin"));
        assert!(reg(RP, 0x05, ORIGIN, "enroll:other").is_err());
    }

    #[test]
    fn enroll_codes_work_once_and_expire() {
        let p = tmp("enroll");
        let code = new_enroll_code(&p, 100).unwrap();
        let rec = load_enroll_code(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p)
                .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777)
                .unwrap(),
            0o600
        );
        guards::enroll_code(&code, &rec.sha256, rec.expires, rec.used, 200).unwrap();
        assert!(guards::enroll_code("WRONGCODE123", &rec.sha256, rec.expires, rec.used, 200).is_err());
        assert!(guards::enroll_code("", &rec.sha256, rec.expires, rec.used, 200).is_err());
        assert!(guards::enroll_code(&code, &rec.sha256, rec.expires, rec.used, 100 + ENROLL_SECS + 1).is_err());
        mark_enroll_code_used(&p, &rec).unwrap();
        let rec = load_enroll_code(&p).unwrap();
        assert!(guards::enroll_code(&code, &rec.sha256, rec.expires, rec.used, 200).is_err());
    }

    #[test]
    fn cbor_rejects_garbage_without_panicking() {
        for g in [
            &b""[..],
            &[0xff],
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x9f],
            &[0xc0, 0x00],
        ] {
            assert!(cbor(g).is_err());
        }
        assert!(auth_data(&[0u8; 36]).is_err());
        let mut d = vec![0u8; 37];
        d[32] = 0x45;
        assert!(auth_data(&d).is_err());
    }

    #[test]
    fn r2_concurrent_assertions_never_fail_on_the_save() {
        // RACE-4
        let (store, soft, ch) = enrolled();
        let store = std::sync::Arc::new(store);
        let ch = std::sync::Arc::new(ch);
        let soft = std::sync::Arc::new(soft);
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (store, ch, soft) = (store.clone(), ch.clone(), soft.clone());
                std::thread::spawn(move || (0..25).filter(|_| attempt(&store, &soft, &ch, OK).is_err()).count())
            })
            .collect();
        let failed: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(failed, 0, "{failed} good assertions failed under concurrency");
    }
}
