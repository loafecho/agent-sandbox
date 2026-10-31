//! The passkey approval page. Listens on 127.0.0.1:8801 only; `tailscale serve` publishes it as
//! https://switchboard.tailnet.example, and the tailnet ACL plus the VM firewall let only the approver's
//! phone reach that. The page itself trusts none of that: every decision needs a WebAuthn assertion
//! from an enrolled passkey with user verification (webauthn.rs), and deny needs one too.
//!
//!   GET  /r/<id>             the request in words, with Approve and Deny
//!   POST /r/<id>/options     {decision} -> a challenge bound to (id, decision, args sha256), 120 s, once
//!   POST /r/<id>/assert      {decision, id, clientDataJSON, authenticatorData, signature} -> decided
//!   GET  /enroll             enrollment page (needs the one-time code from `switchboard enroll-code`)
//!   POST /enroll/options     {code} -> registration challenge
//!   POST /enroll/finish      {code, clientDataJSON, attestationObject} -> passkey stored
//!   GET  /app.js             the page script (CSP: no inline script)
//!
//! Every refusal is audited as `web_refused`. Ten refusals in ten minutes lock the POST routes for the
//! rest of that window.

use crate::approve::Request;
use crate::config::WebCfg;
use crate::guards::{self, Deny};
use crate::mcp::Switchboard;
use crate::webauthn::{self, Challenges, Credentials};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

pub const MAX_WEB_BODY: usize = 16 * 1024;
const LOCK_FAILS: usize = 10;
const LOCK_SECS: u64 = 600;

pub struct Web {
    pub cfg: WebCfg,
    pub challenges: Challenges,
    pub creds: Credentials,
    fails: Mutex<VecDeque<u64>>,
    /// Held across check-code -> verify -> record-used -> store, so one code enrolls one passkey (round 2).
    enroll: Mutex<()>,
}

pub struct WebReply {
    pub status: u16,
    pub ctype: &'static str,
    pub body: String,
}

fn reply(status: u16, ctype: &'static str, body: String) -> WebReply {
    WebReply { status, ctype, body }
}

fn jerr(status: u16, msg: &str) -> WebReply {
    reply(status, "application/json", json!({"error": msg}).to_string())
}

pub const CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

impl Web {
    pub fn new(cfg: WebCfg) -> Web {
        let creds = Credentials::open(&cfg.credentials_file);
        Web {
            cfg,
            challenges: Challenges::new(),
            creds,
            fails: Mutex::new(VecDeque::new()),
            enroll: Mutex::new(()),
        }
    }

    fn locked(&self, now: u64) -> bool {
        let mut f = self.fails.lock().unwrap();
        while f.front().map_or(false, |t| now.saturating_sub(*t) > LOCK_SECS) {
            f.pop_front();
        }
        f.len() >= LOCK_FAILS
    }

    fn failed(&self, now: u64) {
        self.fails.lock().unwrap().push_back(now);
    }
}

pub fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c if c.is_control() => " ".into(),
            c => c.to_string(),
        })
        .collect()
}

fn valid_id(id: &str) -> bool {
    id.len() == 14 && id.starts_with("r-") && id[2..].chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn title(agent: &str) -> String {
    let mut c = agent.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// Who is calling: the X-Forwarded-For tailscale serve set (if any) and the socket peer.
pub struct Caller<'a> {
    pub xff: Option<&'a str>,
    pub peer: &'a str,
}

/// The checks that need only the headers, run before any of the body is read: the device gate, then the
/// declared body size (bigger than MAX_WEB_BODY, or any body on a non-POST). Some(status) = refuse now; the
/// refusal is audited as `web_refused`. `declared` is the request's Content-Length, if it sent one.
pub fn prebody(sb: &Switchboard, caller: &Caller, method: &str, path: &str, declared: Option<usize>) -> Option<u16> {
    let web = sb.web.as_ref()?;
    let path = path.split('?').next().unwrap_or("");
    let (status, why) = match guards::web_device(&web.cfg.allow_src, caller.xff, caller.peer) {
        Err(d) => (403, d.why),
        Ok(()) if declared.map_or(false, |n| n > MAX_WEB_BODY) => (413, "body too large".to_string()),
        Ok(()) if method != "POST" && declared.map_or(false, |n| n > 0) => (400, format!("a body on {method}")),
        Ok(()) => return None,
    };
    sb.audit
        .record(json!({"event": "web_refused", "why": why, "path": path, "from": caller.xff.unwrap_or(caller.peer)}));
    Some(status)
}

/// One web request. `origin` is the request's Origin header (POSTs must carry ours).
pub fn handle(sb: &Switchboard, caller: &Caller, method: &str, path: &str, origin: Option<&str>, body: &[u8], now: u64) -> WebReply {
    let Some(web) = sb.web.as_ref() else { return jerr(404, "not found") };
    let Some(ap) = sb.approvals.as_ref() else { return jerr(404, "not found") };
    let path = path.split('?').next().unwrap_or("");
    if let Err(d) = guards::web_device(&web.cfg.allow_src, caller.xff, caller.peer) {
        sb.audit
            .record(json!({"event": "web_refused", "why": d.why, "path": path, "from": caller.xff.unwrap_or(caller.peer)}));
        return reply(403, "text/plain; charset=utf-8", "Forbidden".into());
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let refuse = |status: u16, req: &str, why: &str| -> WebReply {
        web.failed(now);
        sb.audit.record(json!({"event": "web_refused", "request": req, "why": why, "path": path}));
        jerr(status, why)
    };
    match (method, parts.as_slice()) {
        ("GET", ["app.js"]) => return reply(200, "application/javascript", APP_JS.into()),
        ("GET", ["r", id]) => {
            return match ap.get(id).filter(|_| valid_id(id)) {
                Some(r) => reply(200, "text/html; charset=utf-8", request_page(&r, ap.cfg.window_secs, now)),
                None => reply(404, "text/html; charset=utf-8", page("Not found", "<p>No such request.</p>", "")),
            };
        }
        ("GET", ["enroll"]) => return reply(200, "text/html; charset=utf-8", enroll_page()),
        ("POST", _) => {}
        _ => return jerr(404, "not found"),
    }
    // POST routes from here on.
    if web.locked(now) {
        return jerr(429, "too many failed attempts; try again in 10 minutes");
    }
    if origin != Some(web.cfg.origin.as_str()) {
        return refuse(403, "", "bad Origin header");
    }
    if body.len() > MAX_WEB_BODY {
        return refuse(413, "", "body too large");
    }
    let v: Value = match serde_json::from_slice(body) {
        Ok(v @ Value::Object(_)) => v,
        _ => return refuse(400, "", "body must be a JSON object"),
    };
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    match parts.as_slice() {
        ["r", id, "options"] => {
            let decision = s("decision");
            if !valid_id(id) || !(decision == "approve" || decision == "deny") {
                return refuse(400, id, "bad request id or decision");
            }
            let Some(r) = ap.get(id) else { return refuse(404, id, "unknown request") };
            if r.status != "pending" {
                return jerr(409, &format!("already {}", r.status));
            }
            let ids = web.creds.ids();
            if ids.is_empty() {
                return refuse(403, id, "no passkey is enrolled yet");
            }
            let c = web.challenges.issue(&webauthn::assert_purpose(id, &decision, &r.args_sha256), now);
            json_ok(json!({"challenge": c, "rpId": web.cfg.rp_id, "allow": ids, "timeout": webauthn::CHALLENGE_SECS * 1000}))
        }
        ["r", id, "assert"] => {
            let decision = s("decision");
            if !valid_id(id) || !(decision == "approve" || decision == "deny") {
                return refuse(400, id, "bad request id or decision");
            }
            let Some(r) = ap.get(id) else { return refuse(404, id, "unknown request") };
            let decoded = (|| -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Deny> {
                Ok((
                    webauthn::b64d(&s("clientDataJSON"))?,
                    webauthn::b64d(&s("authenticatorData"))?,
                    webauthn::b64d(&s("signature"))?,
                ))
            })();
            let (cd, ad, sig) = match decoded {
                Ok(t) => t,
                Err(d) => return refuse(400, id, &d.why),
            };
            let challenge = webauthn::client_data(&cd).map(|c| c.challenge).unwrap_or_default();
            let issued = web.challenges.take(&challenge);
            let purpose = webauthn::assert_purpose(id, &decision, &r.args_sha256);
            if let Err(d) = web
                .creds
                .verify(&web.cfg.rp_id, &web.cfg.origin, &s("id"), &cd, &ad, &sig, issued.as_ref(), &purpose, now)
            {
                return refuse(d.code, id, &d.why);
            }
            let to = if decision == "approve" { "approved" } else { "denied" };
            let Some(c) = ap.claim(id, to, "passkey", now) else {
                let st = ap.get(id).map(|r| r.status).unwrap_or_default();
                sb.audit.record(json!({"event": "web_late", "request": id, "decision": decision, "status": st}));
                return jerr(409, &format!("already decided: {st}"));
            };
            sb.audit.record(json!({"event": "web_decided", "request": id, "decision": decision}));
            if to == "approved" {
                ap.execute(&sb.backends, &sb.audit, &c, "passkey", " (approved with passkey)", now);
                let done = ap.get(id).map(|r| r.status).unwrap_or_default();
                json_ok(
                    json!({"status": done, "message": if done == "executed" { "Approved. It ran." } else { "Approved, but it failed. Details are in Discord." }}),
                )
            } else {
                ap.finish_denied(&c, &sb.audit, "passkey", " (denied with passkey)", now);
                json_ok(json!({"status": "denied", "message": "Denied. Nothing ran."}))
            }
        }
        ["enroll", "options"] => {
            let rec = webauthn::load_enroll_code(&web.cfg.enroll_file);
            let code = s("code");
            let used_file = webauthn::used_file(&web.cfg.credentials_file);
            let ok = rec
                .as_ref()
                .map(|r| guards::enroll_code(&code, &r.sha256, r.expires, r.used || webauthn::code_used(&used_file, &r.sha256), now))
                .unwrap_or(Err(Deny {
                    code: 403,
                    why: "enroll: no code".into(),
                }));
            if let Err(d) = ok {
                return refuse(403, "", &d.why);
            }
            let sha = rec.map(|r| r.sha256).unwrap_or_default();
            let c = web.challenges.issue(&format!("enroll:{sha}"), now);
            json_ok(json!({"challenge": c, "rpId": web.cfg.rp_id, "userId": webauthn::b64e(&webauthn::random(16)),
                           "exclude": web.creds.ids(), "timeout": webauthn::CHALLENGE_SECS * 1000}))
        }
        ["enroll", "finish"] => {
            let _one_at_a_time = web.enroll.lock().unwrap();
            let used_file = webauthn::used_file(&web.cfg.credentials_file);
            let Some(rec) = webauthn::load_enroll_code(&web.cfg.enroll_file) else {
                return refuse(403, "", "enroll: no code");
            };
            if let Err(d) = guards::enroll_code(
                &s("code"),
                &rec.sha256,
                rec.expires,
                rec.used || webauthn::code_used(&used_file, &rec.sha256),
                now,
            ) {
                return refuse(403, "", &d.why);
            }
            let decoded = (|| -> Result<(Vec<u8>, Vec<u8>), Deny> { Ok((webauthn::b64d(&s("clientDataJSON"))?, webauthn::b64d(&s("attestationObject"))?)) })();
            let (cd, att) = match decoded {
                Ok(t) => t,
                Err(d) => return refuse(400, "", &d.why),
            };
            let challenge = webauthn::client_data(&cd).map(|c| c.challenge).unwrap_or_default();
            let issued = web.challenges.take(&challenge);
            let cred = match webauthn::verify_registration(
                &web.cfg.rp_id,
                &web.cfg.origin,
                &cd,
                &att,
                issued.as_ref(),
                &format!("enroll:{}", rec.sha256),
                now,
            ) {
                Ok(c) => c,
                Err(d) => return refuse(d.code, "", &d.why),
            };
            if let Err(e) = webauthn::record_code_used(&used_file, &rec.sha256) {
                return jerr(500, &e);
            }
            let short = cred.id.chars().take(8).collect::<String>();
            if let Err(e) = web.creds.add(cred) {
                return refuse(409, "", &e);
            }
            sb.audit.record(json!({"event": "enrolled", "credential": short, "count": web.creds.count()}));
            json_ok(json!({"status": "enrolled", "message": "Passkey is set up. Approval requests now open here."}))
        }
        _ => jerr(404, "not found"),
    }
}

fn json_ok(v: Value) -> WebReply {
    reply(200, "application/json", v.to_string())
}

fn page(head: &str, body: &str, data: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
<meta name=referrer content=no-referrer><title>{}</title><style>body{{font:17px -apple-system,system-ui,sans-serif;margin:0;padding:24px;max-width:520px}}\
h1{{font-size:22px}}button{{font-size:18px;padding:14px 18px;margin:8px 8px 0 0;border-radius:10px;border:0}}#yes{{background:#1f8f4e;color:#fff}}\
#no{{background:#b3261e;color:#fff}}#go{{background:#2a5bd7;color:#fff}}.muted{{color:#666;font-size:14px}}#msg{{margin-top:18px;font-weight:600}}\
input{{font-size:20px;padding:10px;letter-spacing:2px;width:14ch}}</style></head><body {data}><h1>{}</h1>{body}<p id=msg></p>\
<script src=/app.js></script></body></html>",
        esc(head),
        esc(head)
    )
}

fn request_page(r: &Request, window: u64, now: u64) -> String {
    let what = if r.summary.is_empty() { r.tool.clone() } else { r.summary.clone() };
    let expires = r.created + window;
    let open = r.status == "pending" && now < expires;
    let body = if open {
        format!(
            "<p><b>{} wants to {}.</b></p><p class=muted>Request {} · open until <span id=exp data-ts={expires}></span></p>\
<button id=yes>Approve with passkey</button><button id=no>Deny</button>",
            esc(&title(&r.agent)),
            esc(&what),
            esc(&r.id)
        )
    } else {
        format!(
            "<p>{} wanted to {}.</p><p><b>This request is {}.</b></p><p class=muted>Request {}</p>",
            esc(&title(&r.agent)),
            esc(&what),
            esc(&r.status),
            esc(&r.id)
        )
    };
    page("Approval request", &body, &format!("data-request=\"{}\"", esc(&r.id)))
}

fn enroll_page() -> String {
    page(
        "Set up passkey",
        "<p>Enter the one-time code from <code>switchboard enroll-code</code>, then confirm with passkey.</p>\
<p><input id=code autocomplete=off autocapitalize=characters spellcheck=false maxlength=16></p><button id=go>Set up passkey</button>",
        "data-enroll=\"1\"",
    )
}

pub const APP_JS: &str = r#"'use strict';
const $ = s => document.querySelector(s);
const b64d = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const b64e = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const msg = (t, bad) => { const m = $('#msg'); m.textContent = t; m.style.color = bad ? '#b3261e' : '#1f8f4e'; };
async function post(url, body) {
  const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  let j; try { j = await r.json(); } catch (e) { j = {}; }
  if (!r.ok && !j.error) j.error = 'HTTP ' + r.status;
  return j;
}
function lock(on) { document.querySelectorAll('button').forEach(b => b.disabled = on); }
async function decide(decision) {
  const id = document.body.dataset.request;
  lock(true); msg('Waiting for passkey…');
  const o = await post('/r/' + id + '/options', {decision});
  if (o.error) { lock(false); return msg(o.error, true); }
  let cred;
  try {
    cred = await navigator.credentials.get({publicKey: {challenge: b64d(o.challenge), rpId: o.rpId, timeout: o.timeout,
      allowCredentials: o.allow.map(x => ({type: 'public-key', id: b64d(x)})), userVerification: 'required'}});
  } catch (e) { lock(false); return msg('Passkey approval was cancelled. Nothing was decided.', true); }
  const a = cred.response;
  const r = await post('/r/' + id + '/assert', {decision, id: b64e(cred.rawId), clientDataJSON: b64e(a.clientDataJSON),
    authenticatorData: b64e(a.authenticatorData), signature: b64e(a.signature)});
  if (r.error) { lock(false); return msg(r.error, true); }
  msg(r.message, r.status === 'failed');
}
async function enroll() {
  const code = $('#code').value.trim().toUpperCase();
  lock(true); msg('Checking the code…');
  const o = await post('/enroll/options', {code});
  if (o.error) { lock(false); return msg(o.error, true); }
  let cred;
  try {
    cred = await navigator.credentials.create({publicKey: {challenge: b64d(o.challenge), rp: {id: o.rpId, name: 'switchboard'},
      user: {id: b64d(o.userId), name: 'approver', displayName: 'Approver'}, pubKeyCredParams: [{type: 'public-key', alg: -7}],
      authenticatorSelection: {userVerification: 'required', residentKey: 'preferred'}, attestation: 'none', timeout: o.timeout,
      excludeCredentials: o.exclude.map(x => ({type: 'public-key', id: b64d(x)}))}});
  } catch (e) { lock(false); return msg('Passkey setup was cancelled.', true); }
  const r = await post('/enroll/finish', {code, clientDataJSON: b64e(cred.response.clientDataJSON), attestationObject: b64e(cred.response.attestationObject)});
  if (r.error) { lock(false); return msg(r.error, true); }
  msg(r.message);
}
const exp = $('#exp'); if (exp) exp.textContent = new Date(Number(exp.dataset.ts) * 1000).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'});
if ($('#yes')) $('#yes').addEventListener('click', () => decide('approve'));
if ($('#no')) $('#no').addEventListener('click', () => decide('deny'));
if ($('#go')) $('#go').addEventListener('click', enroll);
"#;
