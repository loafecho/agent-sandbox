//! The phone push for an approval request: one POST to the self-hosted ntfy on topic `approvals`, with a
//! link to the passkey page. The connection goes to the pinned tailnet IP (the VM's firewall allows 443
//! to that address only) while TLS still checks the name ntfy.tailnet.example. Carries the summary and
//! the link, never the arguments or a secret. The token (write-only on ntfy) comes from NTFY_TOKEN.

use crate::approve::Notify;
use serde_json::{json, Value};

pub struct HttpNtfy {
    url: String,
    topic: String,
    auth: String,
    agent: ureq::Agent,
}

impl HttpNtfy {
    pub fn new(url: &str, topic: &str, token: &str, pin_ip: Option<&str>) -> Result<HttpNtfy, String> {
        let url = url.trim_end_matches('/').to_string();
        let host = url.trim_start_matches("https://").split(['/', ':']).next().unwrap_or("").to_string();
        let pin: Option<std::net::IpAddr> = match pin_ip {
            Some(p) => Some(p.parse().map_err(|_| format!("ntfy: pin_ip {p} is not an IP"))?),
            None => None,
        };
        let resolver = move |addr: &str| -> std::io::Result<Vec<std::net::SocketAddr>> {
            use std::net::ToSocketAddrs;
            match pin {
                // Only the configured host maps to the pin; any other name resolves to nothing.
                Some(ip) if addr.split(':').next() == Some(host.as_str()) => Ok(vec![std::net::SocketAddr::new(ip, 443)]),
                Some(_) => Ok(vec![]),
                None => Ok(addr.to_socket_addrs()?.collect()),
            }
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .redirects(0)
            .max_idle_connections(0)
            .resolver(resolver)
            .build();
        Ok(HttpNtfy {
            url,
            topic: topic.into(),
            auth: format!("Bearer {token}"),
            agent,
        })
    }
}

impl Notify for HttpNtfy {
    fn publish(&self, title: &str, message: &str, click: &str) -> Result<String, String> {
        let body = json!({
            "topic": self.topic, "title": title, "message": message, "priority": 4, "tags": ["lock"],
            "click": click, "actions": [{"action": "view", "label": "Review", "url": click, "clear": true}]
        });
        let r = self
            .agent
            .post(&self.url)
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| match e {
                ureq::Error::Status(c, _) => format!("ntfy HTTP {c}"),
                ureq::Error::Transport(t) => format!("ntfy transport error: {}", t.kind()),
            })?;
        let v: Value = serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null);
        v["id"].as_str().map(String::from).ok_or_else(|| "ntfy: no message id".into())
    }
}
