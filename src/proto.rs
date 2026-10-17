// SPDX-FileCopyrightText: 2026 Michael McClanahan
// SPDX-License-Identifier: GPL-3.0-or-later

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REQ_PREFIX: &str = "primeapprove:v1:";
pub const RES_PREFIX: &str = "primeapprove:v1r:";
const REQ_DOMAIN: &[u8] = b"primeapprove-req-v1\n";
const RES_DOMAIN: &[u8] = b"primeapprove-res-v1\n";
/// Pairing: the agent's offer (signed by the agent key it wants paired, proving it holds that key)
/// and the Prime's answer (signed by the app key the agent must pin).
pub const PAIR_PREFIX: &str = "primeapprove:pair:v1:";
pub const PAIRED_PREFIX: &str = "primeapprove:paired:v1:";
const PAIR_DOMAIN: &[u8] = b"primeapprove-pair-v1\n";
const PAIRED_DOMAIN: &[u8] = b"primeapprove-paired-v1\n";
const PAIR_CODE_DOMAIN: &[u8] = b"prime-approve pair v1";
/// Names are given by the person on the Prime, never by the agent.
pub const MAX_AGENT_NAME: usize = 24;
/// Most agents a Prime keeps paired at once.
pub const MAX_AGENTS: usize = 5;
pub const MAX_QR: usize = 800;
pub const MAX_TITLE: usize = 60;
pub const MAX_DETAILS: usize = 280;
/// Structured summary limits (see `summary_line`).
pub const MAX_OBJECT: usize = 24;
pub const MAX_TARGET: usize = 40;
/// The only verbs the summary line may show. Anything else rejects the request.
pub const VERBS: [&str; 10] = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Run", "Grant", "Change"];
/// Verbs that always show the "High impact" band, whatever `risk` the agent sent.
/// The agent can raise a request to elevated, but it can never lower one of these to routine.
pub const HIGH_IMPACT_VERBS: [&str; 8] = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Grant"];
/// A request may not expire more than this far in the future (plus `CLOCK_SKEW_SECS`).
/// Short windows limit how long a captured request stays usable.
pub const MAX_LIFETIME_SECS: u64 = 600;
pub const CLOCK_SKEW_SECS: u64 = 60;

/// The demo's action bytes: a real, already-merged PR, pinned to its head commit so the hash covers
/// exactly which code would be merged. The agent hashes these exact bytes; the Prime never re-serializes.
pub const DEMO_ACTION: &[u8] = br#"{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}"#;

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
    TooFarAhead,
}

/// What the agent shows to pair. No name: the person names the agent on the Prime.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PairOffer {
    /// Agent Ed25519 public key, 64 hex chars.
    pub pk: String,
    pub exp: u64,
}

/// What the Prime shows back after the person taps Pair.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PairedReply {
    /// Key id of the agent key that was paired.
    pub kid: String,
    /// The Prime's app public key, 64 hex chars. The agent pins this.
    pub app_pk: String,
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
/// chars ("1594 E5CC"). Glyph i (i = 0..8) comes from byte b = h[4 + i]:
///   color id = b & 0b111        (low 3 bits)  -> GLYPH_RGB / GLYPH_COLORS
///   shape id = (b >> 3) & 0b11  (bits 3 and 4) -> 0 filled circle, 1 filled square, 2 ring, 3 outlined square
/// Bits 5..7 of each byte are unused. Bytes 12..32 are not shown.
///
/// Test vector (the main.rs demo action, see `tests::demo_vector`):
///   action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}
///   hash   = 1594e5cc61b278e99dba75aad80d8b2dd41e135820630c1e12584dda3b95d9d8
///   code   = 1594 E5CC
///   bytes  = 61 b2 78 e9 9d ba 75 aa
///   ids    = (color, shape) (1,0) (2,2) (0,3) (1,1) (5,3) (2,3) (5,2) (2,1)
///   glyphs = orange circle, yellow ring, vermillion outlined square, orange square,
///            blue outlined square, yellow outlined square, blue ring, yellow square
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

/// The one-line summary the app draws, e.g. "Merge → PR #2 → typewright-website-audit".
/// The arrows are added here; agents can't send them.
pub fn summary_line(req: &Request) -> Option<String> {
    summary_parts(req).ok().flatten().map(|(v, o, t)| format!("{v} → {o} → {t}"))
}

pub fn fingerprint(pk: &VerifyingKey) -> String {
    let d = Sha256::digest(pk.as_bytes());
    format!("{}…{}", hex::encode(&d[..4]), hex::encode(&d[28..]))
}

/// Display text is an allowlist: printable ASCII (space through `~`), plus newline in details.
/// Anything else (control, bidi, zero-width, line separators, soft hyphens, tag characters,
/// look-alike letters from other scripts, blank fillers) rejects the request, because it could
/// hide, reorder or disguise text on the Review screen.
fn unsafe_char(c: char, allow_newline: bool) -> bool {
    if c == '\n' { return !allow_newline; }
    !matches!(c, ' '..='~')
}

pub fn text_is_safe(title: &str, details: &str) -> bool {
    !title.chars().any(|c| unsafe_char(c, false)) && !details.chars().any(|c| unsafe_char(c, true))
}

/// Whether the Review screen shows the "High impact" band. The verb decides when there is one;
/// the agent's `risk` can only raise it.
pub fn is_elevated(req: &Request) -> bool {
    req.risk == "elevated" || req.verb.as_deref().is_some_and(|v| HIGH_IMPACT_VERBS.contains(&v))
}

/// Time checks, run after `decode_request` once the clock is known.
pub fn check_time(req: &Request, now: u64) -> Result<(), Reject> {
    check_exp(req.exp, now)
}

fn check_exp(exp: u64, now: u64) -> Result<(), Reject> {
    if exp <= now { return Err(Reject::Expired); }
    if exp > now + MAX_LIFETIME_SECS + CLOCK_SKEW_SECS { return Err(Reject::TooFarAhead); }
    Ok(())
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

// ---------------------------------------------------------------- pairing

/// A name the person typed for an agent: printable ASCII, 1 to 24 chars, no leading/trailing spaces.
pub fn valid_agent_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_AGENT_NAME).contains(&n) && name.trim() == name && !name.chars().any(|c| unsafe_char(c, false))
}

/// Pairing code shown on BOTH screens: the first 12 bytes of
/// SHA-256("prime-approve pair v1" || agent_pk || app_pk), as 6 groups of 4 uppercase hex chars.
/// If someone swapped either key on the way, the two screens show different codes.
pub fn pairing_code(agent_pk: &VerifyingKey, app_pk: &VerifyingKey) -> String {
    let d = Sha256::digest([PAIR_CODE_DOMAIN, agent_pk.as_bytes(), app_pk.as_bytes()].concat());
    let h = hex::encode_upper(&d[..12]);
    (0..6).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(" ")
}

fn split_signed<'q>(qr: &'q str, prefix: &str) -> Result<(Vec<u8>, Signature), Reject> {
    if qr.len() > MAX_QR { return Err(Reject::TooLarge(qr.len())); }
    let rest = qr.strip_prefix(prefix).ok_or(Reject::Malformed("wrong prefix"))?;
    let (b, s) = rest.split_once('.').ok_or(Reject::Malformed("missing signature"))?;
    let body = B64.decode(b).map_err(|_| Reject::Malformed("bad body encoding"))?;
    let sig = B64.decode(s).map_err(|_| Reject::Malformed("bad signature encoding"))?;
    let sig = Signature::from_slice(&sig).map_err(|_| Reject::Malformed("bad signature length"))?;
    Ok((body, sig))
}

fn parse_pk(hex_pk: &str) -> Option<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hex_pk).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&b).ok()
}

/// Agent side (and the demo): the pairing offer QR, signed by the key being offered.
pub fn encode_pair_offer(agent: &SigningKey, exp: u64) -> String {
    let body = serde_json::to_vec(&PairOffer { pk: hex::encode(agent.verifying_key().as_bytes()), exp }).unwrap();
    let sig = agent.sign(&[PAIR_DOMAIN, &body].concat());
    format!("{PAIR_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()))
}

/// Prime side: checks a pairing offer and returns the agent key. The signature only proves the
/// agent holds that key; whether it is the RIGHT agent is decided by the person comparing the
/// pairing code on both screens.
pub fn decode_pair_offer(qr: &str, now: Option<u64>) -> Result<VerifyingKey, Reject> {
    let (body, sig) = split_signed(qr, PAIR_PREFIX)?;
    let offer: PairOffer = serde_json::from_slice(&body).map_err(|_| Reject::Malformed("bad body"))?;
    let pk = parse_pk(&offer.pk).ok_or(Reject::Malformed("agent key must be 32-byte hex"))?;
    pk.verify_strict(&[PAIR_DOMAIN, &body].concat(), &sig).map_err(|_| Reject::BadSignature)?;
    if let Some(now) = now { check_exp(offer.exp, now)?; }
    Ok(pk)
}

/// Prime side: the answer QR, signed by the app key.
pub fn encode_paired_reply(agent_pk: &VerifyingKey, app: &SigningKey) -> String {
    let body = serde_json::to_vec(&PairedReply { kid: kid(agent_pk), app_pk: hex::encode(app.verifying_key().as_bytes()) }).unwrap();
    let sig = app.sign(&[PAIRED_DOMAIN, &body].concat());
    format!("{PAIRED_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()))
}

/// Agent side: checks the Prime's answer and returns the app key to PIN. From then on the agent
/// must check every reply against this pinned key (`verify_reply`) and reject any other key.
/// The agent must also show `pairing_code(own_pk, app_pk)` so the person can compare it.
pub fn verify_paired_reply(qr: &str, agent_pk: &VerifyingKey) -> Option<VerifyingKey> {
    let (body, sig) = split_signed(qr, PAIRED_PREFIX).ok()?;
    let r: PairedReply = serde_json::from_slice(&body).ok()?;
    let app_pk = parse_pk(&r.app_pk)?;
    app_pk.verify_strict(&[PAIRED_DOMAIN, &body].concat(), &sig).ok()?;
    (r.kid == kid(agent_pk)).then_some(app_pk)
}

// ---------------------------------------------------------------- pairing: pending, then confirm

/// A paired agent as saved on the Prime. `name` is what the person typed; the agent never names itself.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Paired {
    pub name: String,
    /// Agent Ed25519 public key, hex.
    pub pk: String,
    pub paired_at: u64,
}

/// A pairing the person started (tapped Pair) but hasn't confirmed yet. Memory only, never saved:
/// leaving the answer screen any other way, or relaunching, throws it away.
#[derive(Clone, Debug)]
pub struct PendingPair {
    pub pk: VerifyingKey,
    pub name: String,
}

/// The person's answer on the answer screen, after comparing the code on the agent's screen.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PairAnswer { CodesMatch, DontMatch }

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PairOutcome {
    /// New agent saved.
    Saved,
    /// Already paired: the saved name was updated.
    Renamed,
    /// Nothing saved (Don't match, or no pending pairing).
    Discarded,
    /// Nothing saved: already MAX_AGENTS paired.
    Full,
}

/// Resolves a pending pairing. Only `CodesMatch` with a pending pairing changes `saved`; the caller
/// persists `saved` when the outcome is `Saved` or `Renamed`.
pub fn resolve_pairing(saved: &mut Vec<Paired>, pending: Option<PendingPair>, answer: PairAnswer, now: u64) -> PairOutcome {
    let Some(p) = pending else { return PairOutcome::Discarded };
    if answer != PairAnswer::CodesMatch || !valid_agent_name(&p.name) { return PairOutcome::Discarded; }
    let hexpk = hex::encode(p.pk.as_bytes());
    if let Some(x) = saved.iter_mut().find(|x| x.pk == hexpk) {
        x.name = p.name;
        return PairOutcome::Renamed;
    }
    if saved.len() >= MAX_AGENTS { return PairOutcome::Full; }
    saved.push(Paired { name: p.name, pk: hexpk, paired_at: now });
    PairOutcome::Saved
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO_HASH: &str = "1594e5cc61b278e99dba75aad80d8b2dd41e135820630c1e12584dda3b95d9d8";

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
        assert_eq!(action_code(&h), "1594 E5CC");
        assert_eq!(glyphs(&h), vec![(1, 0), (2, 2), (0, 3), (1, 1), (5, 3), (2, 3), (5, 2), (2, 1)]);
        assert_eq!(named(&h), [
            "orange circle", "yellow ring", "vermillion outlined square", "orange square",
            "blue outlined square", "yellow outlined square", "blue ring", "yellow square",
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
            title: "Merge PR #2 into main".into(),
            details: "Squash merge at 33393c6.\n10 files changed.".into(),
            risk: "elevated".into(),
            hash: DEMO_HASH.into(),
            exp: 1_792_000_000,
            verb: verb.map(Into::into), object: object.map(Into::into), target: target.map(Into::into),
        };
        (req, sk)
    }

    #[test]
    fn summary_roundtrip_and_size() {
        let (req, sk) = demo_req(Some("Merge"), Some("PR #2"), Some("typewright-website-audit"));
        let qr = encode_request(&req, &sk);
        println!("demo request with summary: {} bytes (cap {MAX_QR})", qr.len());
        assert!(qr.len() <= 600, "demo request is {} bytes; keep it <= 600 for real-camera scanning", qr.len());
        let agents = [Agent::new("Cos (demo agent)", sk.verifying_key())];
        let (r, _) = decode_request(&qr, &agents).expect("valid");
        assert_eq!(summary_line(&r).as_deref(), Some("Merge → PR #2 → typewright-website-audit"));

        let (plain, sk) = demo_req(None, None, None);
        let qr = encode_request(&plain, &sk);
        println!("demo request without summary: {} bytes", qr.len());
        let (r, _) = decode_request(&qr, &agents).expect("old format still valid");
        assert_eq!(summary_line(&r), None);
    }

    #[test]
    fn summary_rejects_bad_input() {
        let (req, sk) = demo_req(Some("Merge"), Some("PR #2"), Some("typewright-website-audit"));
        let agents = [Agent::new("x", sk.verifying_key())];
        let long = "x".repeat(MAX_OBJECT + 1);
        let bad = [
            (Some("Approve"), Some("PR #2"), Some("t")),            // verb not on the list
            (Some("Merge"), Some("PR → #2"), Some("t")),            // fake separator
            (Some("Merge"), Some("PR #2"), Some("a\u{202E}b")),     // bidi override
            (Some("Merge"), Some("PR #2"), None),                   // partial
            (Some("Merge"), Some(" PR #2"), Some("t")),             // padding
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

    // ---- Review findings (Oct 17, 2026). Each test guards a fix, or pins a known gap. ----

    #[test]
    fn display_text_is_an_allowlist() {
        let (req, sk) = demo_req(None, None, None);
        let agents = [Agent::new("x", sk.verifying_key())];
        // Each of these passed the old denylist.
        for bad in ["\u{2028}", "\u{00AD}", "\u{E0041}", "\u{0430}", "\u{3164}", "\u{2800}", "\u{202E}", "\t"] {
            let mut r = req.clone();
            r.title = format!("Merge PR{bad}2");
            assert!(matches!(decode_request(&encode_request(&r, &sk), &agents), Err(Reject::UnsafeText)), "{bad:?} in title");
            let mut r = req.clone();
            r.details = format!("ok\nfine{bad}");
            assert!(matches!(decode_request(&encode_request(&r, &sk), &agents), Err(Reject::UnsafeText)), "{bad:?} in details");
        }
        let mut r = req.clone();
        r.title = "Merge PR #2: fix [x] ~ok~".into();
        assert!(decode_request(&encode_request(&r, &sk), &agents).is_ok());
    }

    #[test]
    fn expiry_is_capped() {
        let (mut req, _) = demo_req(None, None, None);
        let now = 1_800_000_000;
        req.exp = now + 600;
        assert!(check_time(&req, now).is_ok());
        req.exp = now;
        assert!(matches!(check_time(&req, now), Err(Reject::Expired)));
        req.exp = 4_102_444_800; // year 2100
        assert!(matches!(check_time(&req, now), Err(Reject::TooFarAhead)));
    }

    #[test]
    fn high_impact_verbs_cannot_be_downgraded() {
        for v in HIGH_IMPACT_VERBS {
            let (mut r, _) = demo_req(Some(v), Some("x"), Some("y"));
            r.risk = "routine".into();
            assert!(is_elevated(&r), "{v}");
        }
        let (mut r, _) = demo_req(Some("Run"), Some("tests"), Some("ci"));
        r.risk = "routine".into();
        assert!(!is_elevated(&r));
        r.risk = "elevated".into();
        assert!(is_elevated(&r), "agent may raise");
    }

    /// KNOWN GAP (plan item 13): the summary is written by the agent and is not tied to the hash,
    /// so a "Merge PR #2" panel can carry the hash of a repo deletion. Flip this test when the Prime
    /// parses the action bytes itself.
    #[test]
    fn known_gap_summary_not_bound_to_hash() {
        let (mut r, sk) = demo_req(Some("Merge"), Some("PR #2"), Some("typewright-website-audit"));
        r.hash = hex::encode(Sha256::digest(br#"{"tool":"github.delete_repo","repo":"tnvolman/typewright-website-audit"}"#));
        let agents = [Agent::new("x", sk.verifying_key())];
        assert!(decode_request(&encode_request(&r, &sk), &agents).is_ok());
    }

    #[test]
    fn reply_sizes() {
        let (req, _) = demo_req(None, None, None);
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let ok = encode_reply(&req, true, None, &app);
        let no = encode_reply(&req, false, Some("unrecognized"), &app);
        println!("approve reply {} bytes, deny reply {} bytes", ok.len(), no.len());
        assert!(ok.len() <= 450 && no.len() <= 480);
    }

    // ---- Pairing (item 10) ----

    fn agent_sk(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn pairing_roundtrip_and_pinning() {
        let (agent, app) = (agent_sk(1), agent_sk(7));
        let offer = encode_pair_offer(&agent, NOW + 300);
        println!("pair offer {} bytes", offer.len());
        assert!(offer.len() <= 300);
        let pk = decode_pair_offer(&offer, Some(NOW)).expect("valid offer");
        assert_eq!(pk, agent.verifying_key());
        // The offer carries no name: the person names the agent on the Prime.
        let body = String::from_utf8(B64.decode(offer.strip_prefix(PAIR_PREFIX).unwrap().split_once('.').unwrap().0).unwrap()).unwrap();
        assert!(!body.contains("name"));

        let reply = encode_paired_reply(&pk, &app);
        println!("paired reply {} bytes", reply.len());
        let pinned = verify_paired_reply(&reply, &agent.verifying_key()).expect("valid paired reply");
        assert_eq!(pinned, app.verifying_key(), "agent pins the Prime's app key");
        // Wrong agent: the reply names a different kid.
        assert!(verify_paired_reply(&reply, &agent_sk(2).verifying_key()).is_none());

        // After pinning, a reply signed by any other app key must fail.
        let (req, _) = demo_req(None, None, None);
        let impostor = agent_sk(9);
        let fake = encode_reply(&req, true, None, &impostor);
        assert!(!verify_reply(&fake, &pinned, &req.id, &req.kid, &req.hash));
        let real = encode_reply(&req, true, None, &app);
        assert!(verify_reply(&real, &pinned, &req.id, &req.kid, &req.hash));
    }

    #[test]
    fn pair_offer_bad_signature_rejected() {
        let offer = encode_pair_offer(&agent_sk(1), NOW + 300);
        // Re-sign the same body with another key: the offered key didn't sign it.
        let (head, _) = offer.rsplit_once('.').unwrap();
        let body = B64.decode(head.strip_prefix(PAIR_PREFIX).unwrap()).unwrap();
        let other = agent_sk(2).sign(&[PAIR_DOMAIN, &body].concat());
        let forged = format!("{head}.{}", B64.encode(other.to_bytes()));
        assert!(matches!(decode_pair_offer(&forged, Some(NOW)), Err(Reject::BadSignature)));
        // A paired reply with a flipped body byte fails too.
        let reply = encode_paired_reply(&agent_sk(1).verifying_key(), &agent_sk(7));
        let mut b: Vec<char> = reply.chars().collect();
        let i = PAIRED_PREFIX.len() + 10;
        b[i] = if b[i] == 'A' { 'B' } else { 'A' };
        assert!(verify_paired_reply(&b.into_iter().collect::<String>(), &agent_sk(1).verifying_key()).is_none());
        assert!(matches!(decode_pair_offer("primeapprove:pair:v1:x", Some(NOW)), Err(Reject::Malformed(_))));
        assert!(matches!(decode_pair_offer(&"x".repeat(MAX_QR + 1), Some(NOW)), Err(Reject::TooLarge(_))));
    }

    #[test]
    fn pair_offer_expiry_is_capped() {
        let a = agent_sk(1);
        assert!(matches!(decode_pair_offer(&encode_pair_offer(&a, 4_102_444_800), Some(NOW)), Err(Reject::TooFarAhead)));
        assert!(matches!(decode_pair_offer(&encode_pair_offer(&a, NOW - 1), Some(NOW)), Err(Reject::Expired)));
        assert!(decode_pair_offer(&encode_pair_offer(&a, NOW + MAX_LIFETIME_SECS), Some(NOW)).is_ok());
    }

    #[test]
    fn agent_names_are_checked() {
        for ok in ["Cos", "Build bot #2", &"x".repeat(MAX_AGENT_NAME)] { assert!(valid_agent_name(ok), "{ok:?}"); }
        for bad in ["", " Cos", "Cos ", "C\u{0430}s", "Cos\u{202E}", "Cos\tbot", &"x".repeat(MAX_AGENT_NAME + 1)] {
            assert!(!valid_agent_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn pairing_code_matches_both_ways_and_binds_both_keys() {
        let (a, p) = (agent_sk(1).verifying_key(), agent_sk(7).verifying_key());
        let code = pairing_code(&a, &p);
        assert_eq!(code.len(), 29);
        assert_eq!(code.split(' ').count(), 6);
        assert!(code.split(' ').all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))));
        // The agent computes it from its own key and the pinned app key from the paired reply.
        let reply = encode_paired_reply(&a, &agent_sk(7));
        let pinned = verify_paired_reply(&reply, &a).unwrap();
        assert_eq!(pairing_code(&a, &pinned), code);
        assert_ne!(pairing_code(&agent_sk(2).verifying_key(), &p), code, "agent key swapped");
        assert_ne!(pairing_code(&a, &agent_sk(8).verifying_key()), code, "app key swapped");
        assert_ne!(pairing_code(&p, &a), code, "order matters");
        println!("pairing code {code}");
    }

    // ---- Pairing is saved only after the person confirms the codes match (item 10.1) ----

    fn pending(n: u8, name: &str) -> Option<PendingPair> {
        Some(PendingPair { pk: agent_sk(n).verifying_key(), name: name.into() })
    }

    #[test]
    fn pending_pairing_needs_confirmation() {
        let mut saved: Vec<Paired> = Vec::new();
        // Pair tapped, then the screen is left or the app relaunches: the pending pairing is dropped.
        let p = pending(1, "Build bot");
        drop(p);
        assert!(saved.is_empty(), "no confirm, nothing saved");
        assert_eq!(resolve_pairing(&mut saved, None, PairAnswer::CodesMatch, NOW), PairOutcome::Discarded);
        assert!(saved.is_empty(), "confirm with nothing pending saves nothing");
        // Don't match: nothing saved.
        assert_eq!(resolve_pairing(&mut saved, pending(1, "Build bot"), PairAnswer::DontMatch, NOW), PairOutcome::Discarded);
        assert!(saved.is_empty(), "don't match, nothing saved");
        // Codes match: saved, with the name the person typed.
        assert_eq!(resolve_pairing(&mut saved, pending(1, "Build bot"), PairAnswer::CodesMatch, NOW), PairOutcome::Saved);
        assert_eq!(saved, vec![Paired { name: "Build bot".into(), pk: hex::encode(agent_sk(1).verifying_key().as_bytes()), paired_at: NOW }]);
        // Don't match on a re-pair leaves the saved pairing as it was.
        assert_eq!(resolve_pairing(&mut saved, pending(1, "Renamed"), PairAnswer::DontMatch, NOW), PairOutcome::Discarded);
        assert_eq!(saved[0].name, "Build bot");
        assert_eq!(resolve_pairing(&mut saved, pending(1, "Renamed"), PairAnswer::CodesMatch, NOW + 1), PairOutcome::Renamed);
        assert_eq!((saved.len(), saved[0].name.as_str(), saved[0].paired_at), (1, "Renamed", NOW));
    }

    #[test]
    fn pending_pairing_respects_limits() {
        let mut saved: Vec<Paired> = Vec::new();
        for n in 0..MAX_AGENTS as u8 {
            assert_eq!(resolve_pairing(&mut saved, pending(n + 10, "A"), PairAnswer::CodesMatch, NOW), PairOutcome::Saved);
        }
        assert_eq!(resolve_pairing(&mut saved, pending(99, "Extra"), PairAnswer::CodesMatch, NOW), PairOutcome::Full);
        assert_eq!(saved.len(), MAX_AGENTS);
        // A bad name never gets saved, even with a confirm.
        let mut empty: Vec<Paired> = Vec::new();
        assert_eq!(resolve_pairing(&mut empty, pending(1, " bad"), PairAnswer::CodesMatch, NOW), PairOutcome::Discarded);
        assert!(empty.is_empty());
    }
}
