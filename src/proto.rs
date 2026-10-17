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
/// Structured summary limits (see `summary_line`).
pub const MAX_OBJECT: usize = 24;
pub const MAX_TARGET: usize = 40;
/// The only verbs the summary line may show. Anything else rejects the request.
pub const VERBS: [&str; 10] = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Run", "Grant", "Change"];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    pub id: String,
    pub kid: String,
    pub agent: String,
    pub title: String,
    pub details: String,
    /// "routine" or "elevated" (spends money, deletes, merges, sends). Elevated gets an amber band.
    pub risk: String,
    pub hash: String,
    pub exp: u64,
    /// Optional structured summary, shown inside the trusted frame as `verb → object → target`.
    /// All three or none. verb must be one of VERBS; object/target use SUMMARY_CHARS only.
    /// Still agent-supplied and signed, like the title; the app only constrains how it can look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reply {
    pub id: String,
    pub kid: String,
    pub decision: String,
    pub hash: String,
    pub app: String,
    /// Deny only, optional: "wrong_action", "not_now" or "unrecognized".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub const DENY_REASONS: [&str; 3] = ["wrong_action", "not_now", "unrecognized"];

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

/// The 8-character action code shown large on the Review screen and on the agent's screen.
pub fn action_code(hash: &str) -> String {
    let h = hash[..8].to_uppercase();
    format!("{} {}", &h[..4], &h[4..])
}

/// Visual action code palette, indexed by color id. Exact sRGB values; the agent must draw the same ones.
/// Okabe-Ito colorblind-safe palette, with white (#EDEDED) in place of its black so it shows on the
/// dark background. Min CIEDE2000 between any two colors stays >= 10.9 under simulated protanopia,
/// deuteranopia and tritanopia (see docs/colorblind.md).
pub const GLYPH_RGB: [(u8, u8, u8); 8] = [
    (0xD5, 0x5E, 0x00), // 0 vermillion      #D55E00
    (0xE6, 0x9F, 0x00), // 1 orange          #E69F00
    (0xF0, 0xE4, 0x42), // 2 yellow          #F0E442
    (0x00, 0x9E, 0x73), // 3 bluish green    #009E73
    (0x56, 0xB4, 0xE9), // 4 sky blue        #56B4E9
    (0x00, 0x72, 0xB2), // 5 blue            #0072B2
    (0xCC, 0x79, 0xA7), // 6 reddish purple  #CC79A7
    (0xED, 0xED, 0xED), // 7 white           #EDEDED
];
pub const GLYPH_COLORS: [&str; 8] = ["vermillion", "orange", "yellow", "bluish green", "sky blue", "blue", "reddish purple", "white"];
pub const GLYPH_SHAPES: [&str; 4] = ["filled circle", "filled square", "ring", "outlined square"];

/// Visual action code: 8 (color, shape) glyphs, read left to right.
///
/// Input: the request's `hash` field, 64 lowercase/uppercase hex chars = 32 bytes. Prime Approve does
/// not compute this hash; the agent does, as SHA-256 over the exact action bytes it will execute
/// (the demo hashes the literal JSON byte string in main.rs, no re-serialization or canonicalization
/// on the Prime). `decode_request` only checks it is 64 hex chars, and the signature covers it.
///
/// Rule: decode the hex to bytes h[0..32]. The text action code is h[0..4] as 8 uppercase hex
/// chars ("BF35 8E2F"). Glyph i (i = 0..8) comes from byte b = h[4 + i]:
///   color id = b & 0b111        (low 3 bits)  -> GLYPH_RGB / GLYPH_COLORS
///   shape id = (b >> 3) & 0b11  (bits 3 and 4) -> 0 filled circle, 1 filled square, 2 ring, 3 outlined square
/// Bits 5..7 of each byte are unused. Bytes 12..32 are not shown.
///
/// Test vector (the main.rs demo action, see `tests::demo_vector`):
///   action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":3,"method":"squash"}
///   hash   = bf358e2fe2124f3996c349f0eaff5b137d52307d6d31d1d66d4f10785fa6b9df
///   code   = BF35 8E2F
///   bytes  = e2 12 4f 39 96 c3 49 f0
///   ids    = (color, shape) (2,0) (2,2) (7,1) (1,3) (6,2) (3,0) (1,1) (0,2)
///   glyphs = yellow circle, yellow ring, white square, orange outlined square,
///            reddish purple ring, bluish green circle, orange square, vermillion ring
///
/// The pattern helps a person notice a swapped or altered request at a glance. It is not the security
/// boundary: the agent's signature and hash check in `verify_reply` is.
pub fn glyphs(hash: &str) -> Vec<(u8, u8)> {
    let b = hex::decode(hash).unwrap_or_default();
    b.iter().skip(4).take(8).map(|x| (x & 7, (x >> 3) & 3)).collect()
}

/// Characters allowed in summary object/target: ASCII letters, digits, space and `#._/:@-`.
/// No arrows, so an agent can't fake the app-drawn separator.
fn summary_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ' ' | '#' | '.' | '_' | '/' | ':' | '@' | '-')
}

/// Validates the optional summary. Ok(None) when absent, Ok(Some(..)) with the three parts when valid.
pub fn summary_parts(req: &Request) -> Result<Option<(&str, &str, &str)>, &'static str> {
    match (req.verb.as_deref(), req.object.as_deref(), req.target.as_deref()) {
        (None, None, None) => Ok(None),
        (Some(v), Some(o), Some(t)) => {
            if !VERBS.contains(&v) { return Err("summary verb not allowed"); }
            if o.is_empty() || o.len() > MAX_OBJECT || t.is_empty() || t.len() > MAX_TARGET { return Err("summary too long or empty"); }
            if !o.chars().all(summary_char) || !t.chars().all(summary_char) { return Err("summary has disallowed characters"); }
            if o.trim() != o || t.trim() != t { return Err("summary has extra spaces"); }
            Ok(Some((v, o, t)))
        }
        _ => Err("summary needs verb, object and target together"),
    }
}

/// The one-line summary the app draws, e.g. "Merge → PR #3 → typewright-website-audit".
/// The arrows are added here; agents can't send them.
pub fn summary_line(req: &Request) -> Option<String> {
    summary_parts(req).ok().flatten().map(|(v, o, t)| format!("{v} → {o} → {t}"))
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
    if req.risk != "routine" && req.risk != "elevated" { return Err(Reject::Malformed("risk must be routine or elevated")); }
    if !text_is_safe(&req.title, &req.details) || req.agent.chars().any(|c| unsafe_char(c, false)) { return Err(Reject::UnsafeText); }
    summary_parts(&req).map_err(Reject::Malformed)?;
    Ok((req, agent))
}

pub fn encode_reply(req: &Request, approve: bool, reason: Option<&str>, app: &SigningKey) -> String {
    let reason = if approve { None } else { reason.filter(|r| DENY_REASONS.contains(r)).map(String::from) };
    let reply = Reply {
        id: req.id.clone(),
        kid: req.kid.clone(),
        decision: if approve { "approve" } else { "deny" }.into(),
        hash: req.hash.clone(),
        app: hex::encode(app.verifying_key().as_bytes()),
        reason,
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

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO_ACTION: &[u8] = br#"{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":3,"method":"squash"}"#;
    const DEMO_HASH: &str = "bf358e2fe2124f3996c349f0eaff5b137d52307d6d31d1d66d4f10785fa6b9df";

    fn named(hash: &str) -> Vec<String> {
        glyphs(hash).into_iter().map(|(c, s)| {
            let shape = match s { 0 => "circle", 1 => "square", 2 => "ring", _ => "outlined square" };
            format!("{} {}", GLYPH_COLORS[c as usize], shape)
        }).collect()
    }

    #[test]
    fn demo_vector() {
        let h = hex::encode(Sha256::digest(DEMO_ACTION));
        assert_eq!(h, DEMO_HASH);
        assert_eq!(action_code(&h), "BF35 8E2F");
        assert_eq!(glyphs(&h), vec![(2, 0), (2, 2), (7, 1), (1, 3), (6, 2), (3, 0), (1, 1), (0, 2)]);
        assert_eq!(named(&h), [
            "yellow circle", "yellow ring", "white square", "orange outlined square",
            "reddish purple ring", "bluish green circle", "orange square", "vermillion ring",
        ]);
        // Upper-case hex gives the same glyphs.
        assert_eq!(glyphs(&h.to_uppercase()), glyphs(&h));
    }

    fn demo_req(verb: Option<&str>, object: Option<&str>, target: Option<&str>) -> (Request, SigningKey) {
        let sk = SigningKey::from_bytes(&Sha256::digest(b"prime-approve DEMO agent key - public, never use for real").into());
        let req = Request {
            id: "00112233445566778899aabbccddeeff".into(),
            kid: kid(&sk.verifying_key()),
            agent: "Cos (demo agent)".into(),
            title: "Merge PR #3 into main".into(),
            details: "Squash merge, delete branch.\n4 files, checks passed.".into(),
            risk: "elevated".into(),
            hash: DEMO_HASH.into(),
            exp: 1_792_000_000,
            verb: verb.map(Into::into), object: object.map(Into::into), target: target.map(Into::into),
        };
        (req, sk)
    }

    #[test]
    fn summary_roundtrip_and_size() {
        let (req, sk) = demo_req(Some("Merge"), Some("PR #3"), Some("typewright-website-audit"));
        let qr = encode_request(&req, &sk);
        println!("demo request with summary: {} bytes (cap {MAX_QR})", qr.len());
        assert!(qr.len() <= 600, "demo request is {} bytes; keep it <= 600 for real-camera scanning", qr.len());
        let agents = [Agent::new("Cos (demo agent)", sk.verifying_key())];
        let (r, _) = decode_request(&qr, &agents).expect("valid");
        assert_eq!(summary_line(&r).as_deref(), Some("Merge → PR #3 → typewright-website-audit"));

        let (plain, sk) = demo_req(None, None, None);
        let qr = encode_request(&plain, &sk);
        println!("demo request without summary: {} bytes", qr.len());
        let (r, _) = decode_request(&qr, &agents).expect("old format still valid");
        assert_eq!(summary_line(&r), None);
    }

    #[test]
    fn summary_rejects_bad_input() {
        let (req, sk) = demo_req(Some("Merge"), Some("PR #3"), Some("typewright-website-audit"));
        let agents = [Agent::new("x", sk.verifying_key())];
        let long = "x".repeat(MAX_OBJECT + 1);
        let bad = [
            (Some("Approve"), Some("PR #3"), Some("t")),            // verb not on the list
            (Some("Merge"), Some("PR → #3"), Some("t")),            // fake separator
            (Some("Merge"), Some("PR #3"), Some("a\u{202E}b")),     // bidi override
            (Some("Merge"), Some("PR #3"), None),                   // partial
            (Some("Merge"), Some(" PR #3"), Some("t")),             // padding
            (Some("Merge"), Some(long.as_str()), Some("t")), // too long
        ];
        for (v, o, t) in bad {
            let mut r = req.clone();
            r.verb = v.map(Into::into); r.object = o.map(Into::into); r.target = t.map(Into::into);
            let qr = encode_request(&r, &sk);
            assert!(matches!(decode_request(&qr, &agents), Err(Reject::Malformed(_))), "{v:?} {o:?} {t:?}");
        }
    }

    #[test]
    fn approve_reply_verifies_and_deny_does_not() {
        let (req, _) = demo_req(None, None, None);
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let ok = encode_reply(&req, true, Some("not_now"), &app);
        assert!(verify_reply(&ok, &app.verifying_key(), &req.id, &req.kid, &req.hash));
        let body = |q: &str| String::from_utf8(B64.decode(q.strip_prefix(RES_PREFIX).unwrap().split_once('.').unwrap().0).unwrap()).unwrap();
        assert!(!body(&ok).contains("reason")); // never on approve
        let no = encode_reply(&req, false, Some("wrong_action"), &app);
        assert!(body(&no).contains(r#""reason":"wrong_action""#));
        assert!(!verify_reply(&no, &app.verifying_key(), &req.id, &req.kid, &req.hash));
        assert!(!verify_reply(&ok, &app.verifying_key(), &req.id, &req.kid, &"0".repeat(64)));
    }
}
