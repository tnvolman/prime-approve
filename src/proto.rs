use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REQ_PREFIX: &str = "primeapprove:v1:";
pub const RES_PREFIX: &str = "primeapprove:v1r:";
const REQ_DOMAIN: &[u8] = b"primeapprove-req-v1\n";
const RES_DOMAIN: &[u8] = b"primeapprove-res-v1\n";
pub const MAX_QR: usize = 800;
pub const MAX_TITLE: usize = 60;
pub const MAX_DETAILS: usize = 280;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    pub id: String,
    pub kid: String,
    pub agent: String,
    pub title: String,
    pub details: String,
    pub hash: String,
    pub exp: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reply {
    pub id: String,
    pub kid: String,
    pub decision: String,
    pub hash: String,
    pub app: String,
}

pub struct Agent {
    pub name: String,
    pub kid: String,
    pub key: VerifyingKey,
}

impl Agent {
    pub fn new(name: &str, key: VerifyingKey) -> Self {
        Agent { name: name.into(), kid: kid(&key), key }
    }
}

#[derive(Debug)]
pub enum Reject {
    TooLarge(usize),
    Malformed(&'static str),
    UnknownAgent,
    BadSignature,
    UnsafeText,
    AlreadyUsed,
    Expired,
}

/// Key id: first 16 hex chars of SHA-256(public key). Agents are looked up by this, never by display name.
pub fn kid(pk: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(pk.as_bytes())[..8])
}

pub fn fingerprint(pk: &VerifyingKey) -> String {
    let d = Sha256::digest(pk.as_bytes());
    format!("{}…{}", hex::encode(&d[..4]), hex::encode(&d[28..]))
}

/// Control characters (newline allowed in details) and bidi/zero-width formatting characters
/// could hide or reorder text on the Review screen, so any of them rejects the request.
fn unsafe_char(c: char, allow_newline: bool) -> bool {
    if c == '\n' { return !allow_newline; }
    c.is_control()
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{061C}' | '\u{FEFF}')
}

pub fn text_is_safe(title: &str, details: &str) -> bool {
    !title.chars().any(|c| unsafe_char(c, false)) && !details.chars().any(|c| unsafe_char(c, true))
}

pub fn encode_request(req: &Request, agent: &SigningKey) -> String {
    let body = serde_json::to_vec(req).unwrap();
    let sig = agent.sign(&[REQ_DOMAIN, &body].concat());
    format!("{REQ_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()))
}

pub fn decode_request<'a>(qr: &str, agents: &'a [Agent]) -> Result<(Request, &'a Agent), Reject> {
    if qr.len() > MAX_QR { return Err(Reject::TooLarge(qr.len())); }
    let rest = qr.strip_prefix(REQ_PREFIX).ok_or(Reject::Malformed("wrong prefix"))?;
    let (b, s) = rest.split_once('.').ok_or(Reject::Malformed("missing signature"))?;
    let body = B64.decode(b).map_err(|_| Reject::Malformed("bad body encoding"))?;
    let sig = B64.decode(s).map_err(|_| Reject::Malformed("bad signature encoding"))?;
    let sig = Signature::from_slice(&sig).map_err(|_| Reject::Malformed("bad signature length"))?;
    // Verify the exact received bytes against the paired keys BEFORE parsing anything.
    let msg = [REQ_DOMAIN, &body].concat();
    let agent = agents.iter().find(|a| a.key.verify_strict(&msg, &sig).is_ok()).ok_or(Reject::BadSignature)?;
    let req: Request = serde_json::from_slice(&body).map_err(|_| Reject::Malformed("bad body"))?;
    // The signed kid must name the key that actually signed it.
    if req.kid != agent.kid { return Err(Reject::UnknownAgent); }
    if req.id.len() != 32 || hex::decode(&req.id).is_err() { return Err(Reject::Malformed("request id must be 128-bit hex")); }
    if req.hash.len() != 64 || hex::decode(&req.hash).is_err() { return Err(Reject::Malformed("action hash must be SHA-256 hex")); }
    if req.title.chars().count() > MAX_TITLE || req.details.chars().count() > MAX_DETAILS { return Err(Reject::Malformed("title or details too long")); }
    if !text_is_safe(&req.title, &req.details) || req.agent.chars().any(|c| unsafe_char(c, false)) { return Err(Reject::UnsafeText); }
    Ok((req, agent))
}

pub fn encode_reply(req: &Request, approve: bool, app: &SigningKey) -> String {
    let reply = Reply {
        id: req.id.clone(),
        kid: req.kid.clone(),
        decision: if approve { "approve" } else { "deny" }.into(),
        hash: req.hash.clone(),
        app: hex::encode(app.verifying_key().as_bytes()),
    };
    let body = serde_json::to_vec(&reply).unwrap();
    let sig = app.sign(&[RES_DOMAIN, &body].concat());
    format!("{RES_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()))
}

/// Agent-side check: what a real agent must run before acting.
/// The agent must ALSO enforce its own expiry and treat each request id as single-use.
pub fn verify_reply(qr: &str, app_pk: &VerifyingKey, want_id: &str, want_kid: &str, want_hash: &str) -> bool {
    let Some(rest) = qr.strip_prefix(RES_PREFIX) else { return false };
    let Some((b, s)) = rest.split_once('.') else { return false };
    let (Ok(body), Ok(sig)) = (B64.decode(b), B64.decode(s)) else { return false };
    let Ok(sig) = Signature::from_slice(&sig) else { return false };
    if app_pk.verify_strict(&[RES_DOMAIN, &body].concat(), &sig).is_err() { return false; }
    let Ok(r) = serde_json::from_slice::<Reply>(&body) else { return false };
    r.id == want_id && r.kid == want_kid && r.hash == want_hash && r.decision == "approve"
}
