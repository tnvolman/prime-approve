// SPDX-FileCopyrightText: 2026 Michael McClanahan
// SPDX-License-Identifier: GPL-3.0-or-later

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// v2 (item 13): the request carries the raw action bytes; the Prime hashes and parses them itself.
pub const REQ_PREFIX: &str = "primeapprove:v2:";
/// Compact reply (item 11): `PA1:` + base45(packed bytes), all QR alphanumeric-mode characters.
pub const REPLY_PREFIX: &str = "PA1:";
const REQ_DOMAIN: &[u8] = b"primeapprove-req-v2\n";
const REPLY_DOMAIN: &[u8] = b"primeapprove-reply-v1\n";
pub const REPLY_VERSION: u8 = 1;
/// Packed reply: version(1) | decision(1) | request id prefix(8) | time(4, u32 BE unix secs) | sig(64).
pub const REPLY_LEN: usize = 1 + 1 + 8 + 4 + 64;
/// Pairing: the agent's offer (signed by the agent key it wants paired, proving it holds that key)
/// and the Prime's answer (signed by the app key the agent must pin).
pub const PAIR_PREFIX: &str = "primeapprove:pair:v1:";
/// v2 (item 17): the answer carries a fresh 16-byte nonce from the Prime, mixed into the pairing code.
pub const PAIRED_PREFIX: &str = "primeapprove:paired:v2:";
const PAIR_DOMAIN: &[u8] = b"primeapprove-pair-v1\n";
const PAIRED_DOMAIN: &[u8] = b"primeapprove-paired-v2\n";
const PAIR_CODE_DOMAIN: &[u8] = b"prime-approve pair v2";
/// Bytes of the Prime's fresh pairing nonce.
pub const PAIR_NONCE_LEN: usize = 16;
/// Names are given by the person on the Prime, never by the agent.
pub const MAX_AGENT_NAME: usize = 24;
/// Most agents a Prime keeps paired at once.
pub const MAX_AGENTS: usize = 5;
pub const MAX_QR: usize = 800;
pub const MAX_TITLE: usize = 60;
pub const MAX_DETAILS: usize = 280;
/// Most action bytes a request may carry (the whole QR is still capped at MAX_QR).
pub const MAX_ACTION: usize = 400;
/// Verbs that show the "High impact" band. The verb comes from the parsed action, never the agent.
pub const HIGH_IMPACT_VERBS: [&str; 8] = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Grant"];
/// A request may not expire more than this far in the future (plus `CLOCK_SKEW_SECS`).
/// Short windows limit how long a captured request stays usable.
pub const MAX_LIFETIME_SECS: u64 = 600;
pub const CLOCK_SKEW_SECS: u64 = 60;

/// The demo's action bytes: a real, already-merged PR, pinned to its head commit so the hash covers
/// exactly which code would be merged. The agent hashes these exact bytes; the Prime never re-serializes.
pub const DEMO_ACTION: &[u8] = br#"{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"base":"main","method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}"#;

/// A request, v2. The agent's own words (`title`, `details`) are shown only as "Agent says". What the
/// Prime puts in the trusted frame comes from `action`: the exact bytes the agent will run, which the
/// Prime parses (`action_view`) and hashes (`Request::hash`) itself.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub kid: String,
    pub agent: String,
    /// Agent's description, may be empty. Shown small, as "Agent says".
    pub title: String,
    pub details: String,
    /// The exact action bytes (JSON, printable ASCII). SHA-256 of these bytes is the action hash.
    pub action: String,
    pub exp: u64,
}

impl Request {
    /// The action hash, computed BY THE PRIME from the bytes it received: SHA-256(action), hex.
    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.action.as_bytes()))
    }
}

/// What the Prime shows for an action. Built only from the parsed action bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum ActionView {
    /// A tool the Prime knows: every field below is derived by the Prime from the action.
    Known { verb: &'static str, object: String, target: String, detail: String },
    /// Any other tool: the Prime shows the raw action and always marks it high impact.
    Unknown { tool: String },
}

pub const DENY_REASONS: [&str; 3] = ["wrong_action", "not_now", "unrecognized"];

/// Decision byte. A deny reason is folded into it, so every reply is the same length.
pub const DECISION_APPROVE: u8 = 1;
pub const DECISION_DENY: u8 = 2;
/// 3, 4, 5 = deny with DENY_REASONS[0], [1], [2].
const DECISION_DENY_REASON0: u8 = 3;

/// What the agent learns from a reply that verified.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyInfo {
    pub approved: bool,
    /// Deny only: one of DENY_REASONS, or None.
    pub reason: Option<&'static str>,
    /// When the Prime signed it, unix seconds (0 if the Prime's clock was unknown). Signed, informational;
    /// the agent still enforces its own expiry.
    pub at: u32,
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
#[serde(deny_unknown_fields)]
pub struct PairedReply {
    /// Key id of the agent key that was paired.
    pub kid: String,
    /// The Prime's app public key, 64 hex chars. The agent pins this.
    pub app_pk: String,
    /// Fresh random value the Prime picked for this pairing, 32 hex chars. Mixed into the pairing code,
    /// so every pairing shows a new code, even for the same two keys.
    pub nonce: String,
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
/// chars ("F961 B2D1"). Glyph i (i = 0..8) comes from byte b = h[4 + i]:
///   color id = b & 0b111        (low 3 bits)  -> GLYPH_RGB / GLYPH_COLORS
///   shape id = (b >> 3) & 0b11  (bits 3 and 4) -> 0 filled circle, 1 filled square, 2 ring, 3 outlined square
/// Bits 5..7 of each byte are unused. Bytes 12..32 are not shown.
///
/// Test vector (the main.rs demo action, see `tests::demo_vector`):
///   action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"base":"main","method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}
///   hash   = f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d
///   code   = F961 B2D1
///   bytes  = 33 3f b6 d7 ca bf ca 5d
///   ids    = (color, shape) (3,2) (7,3) (6,2) (7,2) (2,1) (7,3) (2,1) (5,3)
///   glyphs = bluish green ring, white outlined square, reddish purple ring, white ring,
///            yellow square, white outlined square, yellow square, blue outlined square
///
/// The pattern helps a person notice a swapped or altered request at a glance. It is not the security
/// boundary: the agent's signature and hash check in `verify_reply` is.
pub fn glyphs(hash: &str) -> Vec<(u8, u8)> {
    let b = hex::decode(hash).unwrap_or_default();
    b.iter().skip(4).take(8).map(|x| (x & 7, (x >> 3) & 3)).collect()
}

// ---------------------------------------------------------------- action registry

/// github.merge_pull_request, the only known tool so far. Unknown fields or duplicate keys reject it
/// (serde refuses both here), so nothing can hide next to the fields the Prime shows.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MergePr {
    #[allow(dead_code)]
    tool: String,
    repo: String,
    pr: u64,
    /// The branch the PR merges INTO. Signed, shown on the Prime ("into main") and checked by the gate,
    /// so a PR retargeted to another base after approval no longer matches (item 16).
    base: String,
    method: String,
    head: String,
}

/// A git branch name for `base`: 1 to 100 of `A-Z a-z 0-9 . _ / -`, not starting with `-` or `/`,
/// no `..` or `//`, not ending in `/` or `.lock`. Every one of these characters is written as itself in
/// JSON (and `\u` is refused), so the base on screen is byte-for-byte the raw text.
pub fn valid_base(b: &str) -> bool {
    (1..=100).contains(&b.len())
        && b.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        && !b.starts_with('-') && !b.starts_with('/')
        && !b.contains("..") && !b.contains("//")
        && !b.ends_with('/') && !b.ends_with(".lock")
}

/// `owner/name`, GitHub's characters only.
fn valid_repo(r: &str) -> bool {
    let mut parts = r.split('/');
    let ok = |p: &str| !p.is_empty() && p.len() <= 100 && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) && p != "." && p != "..";
    matches!((parts.next(), parts.next(), parts.next()), (Some(o), Some(n), None) if ok(o) && ok(n)) && r.len() <= 64
}

/// Action bytes: printable ASCII plus newline, at most MAX_ACTION bytes.
fn action_text_ok(a: &str) -> bool {
    !a.is_empty() && a.len() <= MAX_ACTION && a.chars().all(|c| c == '\n' || (' '..='~').contains(&c))
}

/// No `\u` escapes anywhere in the action. Its bytes are already printable ASCII, so an escape could only
/// smuggle in a character the allowlist refuses (`\u0455`, a Cyrillic look-alike) or make the decoded text
/// differ from the raw text the person reads. `\\u` (an escaped backslash, then `u`) is plain text and allowed.
fn no_unicode_escapes(a: &str) -> bool {
    let mut it = a.chars();
    while let Some(c) = it.next() {
        if c == '\\' && it.next() == Some('u') { return false; }
    }
    true
}

/// Tool names: 1 to 64 of `A-Z a-z 0-9 . _ -`. None of these can be written as a JSON escape other than
/// `\u` (refused above), so the tool name on screen is always byte-for-byte the raw text.
fn valid_tool(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Parses the action bytes into what the Prime shows. Err for anything the Prime must refuse:
/// oversized, non-ASCII, not a JSON object with a string "tool", or a known tool with bad fields.
pub fn action_view(action: &str) -> Result<ActionView, &'static str> {
    if !action_text_ok(action) { return Err("action must be printable ASCII JSON of 400 bytes or less"); }
    if !no_unicode_escapes(action) { return Err("action must not use \\u escapes"); }
    let v: serde_json::Value = serde_json::from_str(action).map_err(|_| "action is not valid JSON")?;
    let tool = v.as_object().and_then(|o| o.get("tool")).and_then(|t| t.as_str()).ok_or("action needs a string \"tool\"")?;
    if !valid_tool(tool) { return Err("tool name must be 1 to 64 of A-Z a-z 0-9 . _ -"); }
    match tool {
        "github.merge_pull_request" => {
            let m: MergePr = serde_json::from_str(action).map_err(|_| "merge action has missing, extra or repeated fields")?;
            if !valid_repo(&m.repo) { return Err("merge action repo must be owner/name"); }
            if !matches!(m.method.as_str(), "merge" | "squash" | "rebase") { return Err("merge method must be merge, squash or rebase"); }
            if m.head.len() != 40 || !m.head.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) { return Err("merge head must be a 40-char lowercase commit SHA"); }
            if m.pr == 0 { return Err("merge pr must be a positive number"); }
            if !valid_base(&m.base) { return Err("merge base must be a branch name (1 to 100 of A-Z a-z 0-9 . _ / -)"); }
            Ok(ActionView::Known { verb: "Merge", object: format!("PR #{} into {}", m.pr, m.base), target: m.repo, detail: format!("{} · head {}", m.method, &m.head[..7]) })
        }
        _ => Ok(ActionView::Unknown { tool: tool.to_string() }),
    }
}

/// The one-line summary inside the trusted frame, e.g. "Merge PR #2 into main → tnvolman/typewright-website-audit".
/// Known tools only; built from the parsed action.
pub fn summary_line(view: &ActionView) -> Option<String> {
    match view {
        ActionView::Known { verb, object, target, .. } => Some(format!("{verb} {object} → {target}")),
        ActionView::Unknown { .. } => None,
    }
}

/// Whether the Review screen shows "High impact": the parsed verb decides, and unknown actions always are.
pub fn is_elevated(view: &ActionView) -> bool {
    match view {
        ActionView::Known { verb, .. } => HIGH_IMPACT_VERBS.contains(verb),
        ActionView::Unknown { .. } => true,
    }
}

/// The raw action wrapped at `width` characters, for the unknown-action view (display only).
pub fn wrap_raw(action: &str, width: usize) -> String {
    action.lines().flat_map(|l| {
        let c: Vec<char> = l.chars().collect();
        if c.is_empty() { vec![String::new()] } else { c.chunks(width).map(|x| x.iter().collect()).collect() }
    }).collect::<Vec<String>>().join("\n")
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

pub fn decode_request<'a>(qr: &str, agents: &'a [Agent]) -> Result<(Request, ActionView, &'a Agent), Reject> {
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
    if req.title.chars().count() > MAX_TITLE || req.details.chars().count() > MAX_DETAILS { return Err(Reject::Malformed("title or details too long")); }
    if !text_is_safe(&req.title, &req.details) || req.agent.chars().any(|c| unsafe_char(c, false)) { return Err(Reject::UnsafeText); }
    if req.action.chars().any(|c| unsafe_char(c, true)) { return Err(Reject::UnsafeText); }
    let view = action_view(&req.action).map_err(Reject::Malformed)?;
    Ok((req, view, agent))
}

// ---------------------------------------------------------------- base45 (RFC 9285)

const B45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// RFC 9285 base45. Every output character is in the QR alphanumeric set, so the QR uses
/// alphanumeric mode (5.5 bits per character).
pub fn base45_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() / 2 * 3 + 2);
    for c in data.chunks(2) {
        let (mut n, k) = if c.len() == 2 { (c[0] as u32 * 256 + c[1] as u32, 3) } else { (c[0] as u32, 2) };
        for _ in 0..k { out.push(B45[(n % 45) as usize] as char); n /= 45; }
    }
    out
}

pub fn base45_decode(s: &str) -> Option<Vec<u8>> {
    let v: Vec<u32> = s.bytes().map(|ch| B45.iter().position(|&x| x == ch).map(|i| i as u32)).collect::<Option<_>>()?;
    if v.len() % 3 == 1 { return None; }
    let mut out = Vec::with_capacity(v.len() / 3 * 2 + 1);
    for c in v.chunks(3) {
        if c.len() == 3 {
            let n = c[0] + c[1] * 45 + c[2] * 45 * 45;
            if n > 0xFFFF { return None; }
            out.extend_from_slice(&[(n >> 8) as u8, n as u8]);
        } else {
            let n = c[0] + c[1] * 45;
            if n > 0xFF { return None; }
            out.push(n as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------- reply

/// The bytes the Prime signs. The FULL request id, the agent's kid and the FULL action hash are bound
/// here even though the QR carries only an 8-byte id prefix: the agent recomputes this message from
/// the request it holds, so a reply only verifies for that exact request and action.
fn reply_message(version: u8, decision: u8, id: &[u8; 16], kid: &[u8; 8], hash: &[u8; 32], at: u32) -> Vec<u8> {
    [REPLY_DOMAIN, &[version, decision], id, kid, hash, &at.to_be_bytes()].concat()
}

fn fixed<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// Prime side: the signed reply QR text, `PA1:` + base45(78 bytes) = 121 characters.
/// `at` is the Prime's clock (unix seconds, 0 if unknown). A reason is only kept on a deny,
/// and only if it is one of DENY_REASONS.
pub fn encode_reply(req: &Request, approve: bool, reason: Option<&str>, app: &SigningKey, at: u64) -> String {
    let decision = if approve {
        DECISION_APPROVE
    } else {
        reason.and_then(|r| DENY_REASONS.iter().position(|x| *x == r)).map_or(DECISION_DENY, |i| DECISION_DENY_REASON0 + i as u8)
    };
    // decode_request already checked id is 32 hex chars and kid matches the agent key.
    // The Prime signs the hash IT computed from the action bytes, never one the agent sent.
    let (id, kid, hash) = (fixed::<16>(&req.id).expect("id"), fixed::<8>(&req.kid).expect("kid"), fixed::<32>(&req.hash()).expect("hash"));
    let at = u32::try_from(at).unwrap_or(0);
    let sig = app.sign(&reply_message(REPLY_VERSION, decision, &id, &kid, &hash, at));
    let mut packed = Vec::with_capacity(REPLY_LEN);
    packed.extend_from_slice(&[REPLY_VERSION, decision]);
    packed.extend_from_slice(&id[..8]);
    packed.extend_from_slice(&at.to_be_bytes());
    packed.extend_from_slice(&sig.to_bytes());
    format!("{REPLY_PREFIX}{}", base45_encode(&packed))
}

/// Agent side: checks a reply against the PINNED Prime key and the request the agent issued
/// (its id, its own kid and the action hash it is about to run). Returns the decision only if
/// everything matches. The agent must ALSO enforce its own expiry and treat each id as single-use.
pub fn decode_reply(qr: &str, app_pk: &VerifyingKey, want_id: &str, want_kid: &str, want_hash: &str) -> Option<ReplyInfo> {
    let b = base45_decode(qr.strip_prefix(REPLY_PREFIX)?)?;
    if b.len() != REPLY_LEN || b[0] != REPLY_VERSION { return None; }
    let (id, kid, hash) = (fixed::<16>(want_id)?, fixed::<8>(want_kid)?, fixed::<32>(want_hash)?);
    if b[2..10] != id[..8] { return None; }
    let decision = b[1];
    if !(DECISION_APPROVE..DECISION_DENY_REASON0 + DENY_REASONS.len() as u8).contains(&decision) { return None; }
    let at = u32::from_be_bytes(b[10..14].try_into().ok()?);
    let sig = Signature::from_slice(&b[14..]).ok()?;
    app_pk.verify_strict(&reply_message(b[0], decision, &id, &kid, &hash, at), &sig).ok()?;
    let reason = (decision >= DECISION_DENY_REASON0).then(|| DENY_REASONS[(decision - DECISION_DENY_REASON0) as usize]);
    Some(ReplyInfo { approved: decision == DECISION_APPROVE, reason, at })
}

/// Agent-side check: what a real agent must run before acting. True only for a valid APPROVE.
pub fn verify_reply(qr: &str, app_pk: &VerifyingKey, want_id: &str, want_kid: &str, want_hash: &str) -> bool {
    decode_reply(qr, app_pk, want_id, want_kid, want_hash).is_some_and(|r| r.approved)
}

// ---------------------------------------------------------------- pairing

/// A name the person typed for an agent: printable ASCII, 1 to 24 chars, no leading/trailing spaces.
pub fn valid_agent_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_AGENT_NAME).contains(&n) && name.trim() == name && !name.chars().any(|c| unsafe_char(c, false))
}

/// Pairing code shown on BOTH screens: the first 12 bytes of
/// SHA-256("prime-approve pair v2" || agent_pk || app_pk || nonce), as 6 groups of 4 uppercase hex chars,
/// where `nonce` is the 16 random bytes the Prime picked for this pairing and sent in its answer.
/// If someone swapped either key (or the nonce) on the way, the two screens show different codes, and
/// no two pairings show the same code.
pub fn pairing_code(agent_pk: &VerifyingKey, app_pk: &VerifyingKey, nonce: &[u8; PAIR_NONCE_LEN]) -> String {
    let d = Sha256::digest([PAIR_CODE_DOMAIN, agent_pk.as_bytes(), app_pk.as_bytes(), nonce].concat());
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

/// Prime side: the answer QR, signed by the app key. `nonce` must be fresh random bytes for this pairing
/// (the same ones the Prime used for the code on its own screen).
pub fn encode_paired_reply(agent_pk: &VerifyingKey, app: &SigningKey, nonce: &[u8; PAIR_NONCE_LEN]) -> String {
    let body = serde_json::to_vec(&PairedReply { kid: kid(agent_pk), app_pk: hex::encode(app.verifying_key().as_bytes()), nonce: hex::encode(nonce) }).unwrap();
    let sig = app.sign(&[PAIRED_DOMAIN, &body].concat());
    format!("{PAIRED_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()))
}

/// Agent side: checks the Prime's answer and returns the app key to PIN and the Prime's nonce. From then
/// on the agent must check every reply against this pinned key (`verify_reply`) and reject any other key.
/// The agent must also show `pairing_code(own_pk, app_pk, nonce)` so the person can compare it.
pub fn verify_paired_reply(qr: &str, agent_pk: &VerifyingKey) -> Option<(VerifyingKey, [u8; PAIR_NONCE_LEN])> {
    let (body, sig) = split_signed(qr, PAIRED_PREFIX).ok()?;
    let r: PairedReply = serde_json::from_slice(&body).ok()?;
    let app_pk = parse_pk(&r.app_pk)?;
    app_pk.verify_strict(&[PAIRED_DOMAIN, &body].concat(), &sig).ok()?;
    let nonce: [u8; PAIR_NONCE_LEN] = fixed(&r.nonce)?;
    if r.nonce != hex::encode(nonce) { return None; } // lowercase hex only, one spelling per nonce
    (r.kid == kid(agent_pk)).then_some((app_pk, nonce))
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

    const DEMO_HASH: &str = "f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d";

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
        assert_eq!(action_code(&h), "F961 B2D1");
        assert_eq!(glyphs(&h), vec![(3, 2), (7, 3), (6, 2), (7, 2), (2, 1), (7, 3), (2, 1), (5, 3)]);
        assert_eq!(named(&h), [
            "bluish green ring", "white outlined square", "reddish purple ring", "white ring",
            "yellow square", "white outlined square", "yellow square", "blue outlined square",
        ]);
        // Upper-case hex gives the same glyphs.
        assert_eq!(glyphs(&h.to_uppercase()), glyphs(&h));
    }

    fn demo_req() -> (Request, SigningKey) {
        let sk = SigningKey::from_bytes(&Sha256::digest(b"prime-approve DEMO agent key - public, never use for real").into());
        let req = Request {
            id: "00112233445566778899aabbccddeeff".into(),
            kid: kid(&sk.verifying_key()),
            agent: "Cos (demo agent)".into(),
            title: "Merge PR #2 into main".into(),
            details: "Squash merge at 33393c6.\n10 files changed.".into(),
            action: std::str::from_utf8(DEMO_ACTION).unwrap().into(),
            exp: 1_792_000_000,
        };
        (req, sk)
    }

    // ---- What the Prime shows (item 13): parsed from the action, hashed by the Prime ----

    #[test]
    fn known_tool_shows_parsed_fields_and_size() {
        let (req, sk) = demo_req();
        let qr = encode_request(&req, &sk);
        println!("demo request: {} bytes (cap {MAX_QR})", qr.len());
        assert!(qr.len() <= 650, "demo request is {} bytes", qr.len());
        let agents = [Agent::new("Cos (demo agent)", sk.verifying_key())];
        let (r, view, _) = decode_request(&qr, &agents).expect("valid");
        assert_eq!(view, ActionView::Known { verb: "Merge", object: "PR #2 into main".into(), target: "tnvolman/typewright-website-audit".into(), detail: "squash · head 33393c6".into() });
        assert_eq!(summary_line(&view).as_deref(), Some("Merge PR #2 into main → tnvolman/typewright-website-audit"));
        assert!(is_elevated(&view));
        assert_eq!(r.hash(), DEMO_HASH, "the Prime computes the hash from the action bytes");
    }

    #[test]
    fn lying_title_cannot_change_the_band() {
        let (mut req, sk) = demo_req();
        let agents = [Agent::new("x", sk.verifying_key())];
        // The agent says "Merge PR #2" but the action merges PR #9 somewhere else.
        req.title = "Merge PR #2 into main".into();
        req.details = "Merge -> PR #2 -> tnvolman/typewright-website-audit".into();
        req.action = r#"{"tool":"github.merge_pull_request","repo":"evil/other-repo","pr":9,"base":"release","method":"merge","head":"0000000000000000000000000000000000000001"}"#.into();
        let (r, view, _) = decode_request(&encode_request(&req, &sk), &agents).unwrap();
        assert_eq!(summary_line(&view).as_deref(), Some("Merge PR #9 into release → evil/other-repo"));
        assert_ne!(r.hash(), DEMO_HASH);
        assert_eq!(r.hash(), hex::encode(Sha256::digest(req.action.as_bytes())));
        // A reply binds the hash of what was shown, not of anything the agent claimed.
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let reply = encode_reply(&r, true, None, &app, AT);
        assert!(!verify_reply(&reply, &app.verifying_key(), &r.id, &r.kid, DEMO_HASH));
        assert!(verify_reply(&reply, &app.verifying_key(), &r.id, &r.kid, &r.hash()));
    }

    #[test]
    fn unknown_tool_gets_raw_view_and_high_impact() {
        let (mut req, sk) = demo_req();
        let agents = [Agent::new("x", sk.verifying_key())];
        req.title = "Run the unit tests".into();
        req.action = r#"{"tool":"github.delete_repo","repo":"tnvolman/typewright-website-audit"}"#.into();
        let (_, view, _) = decode_request(&encode_request(&req, &sk), &agents).unwrap();
        assert_eq!(view, ActionView::Unknown { tool: "github.delete_repo".into() });
        assert!(is_elevated(&view), "unknown is always high impact");
        assert_eq!(summary_line(&view), None);
        assert_eq!(wrap_raw("abcdefgh\nij", 3), "abc\ndef\ngh\nij");
    }

    #[test]
    fn bad_actions_are_rejected() {
        let (req, sk) = demo_req();
        let agents = [Agent::new("x", sk.verifying_key())];
        let head = "33393c61b3e595bfb83bb9b909e280b2f40f0976";
        let big = format!(r#"{{"tool":"x","pad":"{}"}}"#, "a".repeat(MAX_ACTION));
        let bad: Vec<String> = vec![
            "not json".into(),
            "".into(),
            "[1,2]".into(),
            r#"{"tool":7}"#.into(),
            r#"{"repo":"a/b"}"#.into(),
            big,
            "{\"tool\":\"x\",\"t\":\"caf\u{e9}\"}".into(),
            "{\"tool\":\"x\",\"t\":\"a\tb\"}".into(),
            // Known tool with bad fields: each must reject, never fall back to a friendlier view.
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","method":"squash","head":"{head}","delete_branch":true}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","repo":"c/d","pr":2,"base":"main","method":"squash","head":"{head}"}}"#),
            r#"{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","method":"squash"}"#.into(),
            // Item 16: base is required and must be a plain branch name.
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","base":"release","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":7,"method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"ma in","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"-main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"/main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main/","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main.lock","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"a..b","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"a//b","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"m\u0430in","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main~1","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"{}","method":"squash","head":"{head}"}}"#, "b".repeat(101)),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":"2","base":"main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2.5,"base":"main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":0,"base":"main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","method":"force","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a b/c","pr":2,"base":"main","method":"squash","head":"{head}"}}"#),
            format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b/c","pr":2,"base":"main","method":"squash","head":"{head}"}}"#),
            r#"{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","method":"squash","head":"33393C61B3E595BFB83BB9B909E280B2F40F0976"}"#.into(),
            r#"{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"main","method":"squash","head":"33393c6"}"#.into(),
        ];
        for a in bad {
            let mut r = req.clone();
            r.action = a.clone();
            let res = decode_request(&encode_request(&r, &sk), &agents);
            assert!(matches!(res, Err(Reject::Malformed(_)) | Err(Reject::UnsafeText) | Err(Reject::TooLarge(_))), "{a:?} gave {:?}", res.map(|x| x.1));
        }
        // Pretty-printed JSON with newlines is fine; the hash covers the exact bytes.
        let mut r = req.clone();
        r.action = format!("{{\n \"tool\": \"github.merge_pull_request\",\n \"repo\": \"a/b\", \"pr\": 2, \"base\": \"main\",\n \"method\": \"rebase\", \"head\": \"{head}\"\n}}");
        let (r2, v, _) = decode_request(&encode_request(&r, &sk), &agents).unwrap();
        assert_eq!(summary_line(&v).as_deref(), Some("Merge PR #2 into main → a/b"));
        assert_eq!(r2.hash(), hex::encode(Sha256::digest(r.action.as_bytes())));
    }

    /// Item 16: the base branch is part of the signed action, shown on the Prime, and changes the hash.
    #[test]
    fn base_branch_is_shown_and_bound() {
        let head = "33393c61b3e595bfb83bb9b909e280b2f40f0976";
        let act = |base: &str| format!(r#"{{"tool":"github.merge_pull_request","repo":"a/b","pr":2,"base":"{base}","method":"squash","head":"{head}"}}"#);
        let main = action_view(&act("main")).unwrap();
        let rel = action_view(&act("release/2026.10")).unwrap();
        assert_eq!(summary_line(&main).as_deref(), Some("Merge PR #2 into main → a/b"));
        assert_eq!(summary_line(&rel).as_deref(), Some("Merge PR #2 into release/2026.10 → a/b"), "a non-default base is just as visible");
        assert_ne!(Sha256::digest(act("main")), Sha256::digest(act("release/2026.10")), "approving one base never covers another");
        for ok in ["main", "release/1.2", "feature_x-y", "v1.0.x", "a", &"b".repeat(100)] { assert!(valid_base(ok), "{ok:?}"); }
        for bad in ["", "-x", "/x", "x/", "x.lock", "a..b", "a//b", "a b", "a~b", "a^b", "a:b", "a@{1}", "a\\b", "caf\u{e9}", &"b".repeat(101)] {
            assert!(!valid_base(bad), "{bad:?}");
        }
    }

    #[test]
    fn unicode_escapes_cannot_fake_a_tool_name() {
        // "github.merge_pull_requeѕt" with a Cyrillic ѕ written as \u0455: valid JSON, ASCII on the wire.
        let lookalike = r#"{"tool":"github.merge_pull_reque\u0455t","repo":"a/b","pr":2,"base":"main","method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}"#;
        assert!(action_view(lookalike).is_err());
        // An ASCII escape would show "github.delete_repo" for raw text that reads "\u0067ithub...".
        assert!(action_view(r#"{"tool":"\u0067ithub.delete_repo"}"#).is_err());
        assert!(action_view(r#"{"\u0074ool":"ci.run"}"#).is_err());
        assert!(action_view(r#"{"tool":"ci.run","x":"\u0041"}"#).is_err());
        assert!(action_view(r#"{"tool":"ci\/run"}"#).is_err());
        assert!(action_view(r#"{"tool":"ci run"}"#).is_err());
        // An escaped backslash followed by u is plain text, and the tool shown is exactly the raw text.
        let ok = r#"{"tool":"ci.run","note":"a\\u0041"}"#;
        assert_eq!(action_view(ok), Ok(ActionView::Unknown { tool: "ci.run".into() }));
        assert!(ok.contains("\"ci.run\""));
    }

    #[test]
    fn request_rejects_unknown_fields_and_v1() {
        // An old v1-style field (an agent-supplied hash) is refused, not ignored.
        let (req, sk) = demo_req();
        let mut v = serde_json::to_value(&req).unwrap();
        v["hash"] = serde_json::json!(DEMO_HASH);
        let body = serde_json::to_vec(&v).unwrap();
        let sig = sk.sign(&[REQ_DOMAIN, &body].concat());
        let qr = format!("{REQ_PREFIX}{}.{}", B64.encode(&body), B64.encode(sig.to_bytes()));
        let agents = [Agent::new("x", sk.verifying_key())];
        assert!(matches!(decode_request(&qr, &agents), Err(Reject::Malformed(_))));
        assert!(matches!(decode_request(&qr.replacen("primeapprove:v2:", "primeapprove:v1:", 1), &agents), Err(Reject::Malformed(_))));
    }

    const AT: u64 = 1_800_000_000;

    #[test]
    fn approve_reply_verifies_and_deny_does_not() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let pk = app.verifying_key();
        let ok = encode_reply(&req, true, Some("not_now"), &app, AT);
        assert!(verify_reply(&ok, &pk, &req.id, &req.kid, &req.hash()));
        // A reason is never carried on an approve.
        assert_eq!(decode_reply(&ok, &pk, &req.id, &req.kid, &req.hash()), Some(ReplyInfo { approved: true, reason: None, at: AT as u32 }));
        for (i, r) in DENY_REASONS.iter().enumerate() {
            let no = encode_reply(&req, false, Some(r), &app, AT);
            assert_eq!(decode_reply(&no, &pk, &req.id, &req.kid, &req.hash()).unwrap().reason, Some(DENY_REASONS[i]));
            assert!(!verify_reply(&no, &pk, &req.id, &req.kid, &req.hash()), "a deny never verifies as approve");
        }
        // Unknown reasons are dropped, not signed.
        let no = encode_reply(&req, false, Some("because"), &app, AT);
        assert_eq!(decode_reply(&no, &pk, &req.id, &req.kid, &req.hash()), Some(ReplyInfo { approved: false, reason: None, at: AT as u32 }));
    }

    // ---- Compact reply (item 11) ----

    #[test]
    fn base45_matches_rfc9285() {
        for (raw, enc) in [(&b"AB"[..], "BB8"), (b"Hello!!", "%69 VD92EX0"), (b"base-45", "UJCLQE7W581"), (b"ietf!", "QED8WEX0"), (b"", "")] {
            assert_eq!(base45_encode(raw), enc);
            assert_eq!(base45_decode(enc).as_deref(), Some(raw));
        }
        assert_eq!(base45_decode("GGW"), None, "65536 is out of range");
        assert_eq!(base45_decode("ab"), None, "lowercase is not base45");
        assert_eq!(base45_decode("A"), None, "dangling character");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base45_decode(&base45_encode(&all)).unwrap(), all);
    }

    #[test]
    fn compact_reply_roundtrip() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let qr = encode_reply(&req, true, None, &app, AT);
        assert!(qr.starts_with(REPLY_PREFIX));
        // Every character is QR alphanumeric, so the QR uses alphanumeric mode.
        assert!(qr.bytes().all(|c| B45.contains(&c)), "{qr}");
        let raw = base45_decode(&qr[REPLY_PREFIX.len()..]).unwrap();
        assert_eq!(raw.len(), REPLY_LEN);
        assert_eq!(&raw[..2], &[REPLY_VERSION, DECISION_APPROVE]);
        assert_eq!(hex::encode(&raw[2..10]), &req.id[..16], "8-byte request id prefix");
        assert_eq!(u32::from_be_bytes(raw[10..14].try_into().unwrap()), AT as u32);
        assert!(verify_reply(&qr, &app.verifying_key(), &req.id, &req.kid, &req.hash()));
        // Upper-case hex from the agent is fine too.
        assert!(verify_reply(&qr, &app.verifying_key(), &req.id.to_uppercase(), &req.kid, &req.hash().to_uppercase()));
        // Unknown clock signs time 0, and still verifies.
        let q0 = encode_reply(&req, true, None, &app, 0);
        assert_eq!(decode_reply(&q0, &app.verifying_key(), &req.id, &req.kid, &req.hash()).unwrap().at, 0);
    }

    /// Fixed test vector for other implementations (tools/decode_reply.py is checked against it).
    /// App key: SigningKey::from_bytes(&[7; 32]) (a public TEST key). Request: `demo_req`, signed at AT.
    #[test]
    fn compact_reply_test_vector() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let qr = encode_reply(&req, true, None, &app, AT);
        println!("vector app_pk={} id={} kid={} hash={} reply={qr}", hex::encode(app.verifying_key().as_bytes()), req.id, req.kid, req.hash());
        assert_eq!(qr, REPLY_VECTOR);
    }
    const REPLY_VECTOR: &str = "PA1:W50H00PE4XS8-.CFPDUOQEHIDYT2BN5 FYCK3H043P$PR9VC.CVR851BUOKMF P-$F0J0FFB1WVDOMVACB.EN29N2FM 1KTTH0DBBIF7T8DK*MIQV9O4V";

    #[test]
    fn compact_reply_tamper_fails() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let pk = app.verifying_key();
        let qr = encode_reply(&req, true, None, &app, AT);
        let raw = base45_decode(&qr[REPLY_PREFIX.len()..]).unwrap();
        // Flip every bit of every packed byte: none may verify (decision, id prefix, time and sig all bound).
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut t = raw.clone();
                t[i] ^= 1 << bit;
                let q = format!("{REPLY_PREFIX}{}", base45_encode(&t));
                assert!(decode_reply(&q, &pk, &req.id, &req.kid, &req.hash()).is_none(), "byte {i} bit {bit}");
            }
        }
        // A deny can't be turned into an approve by editing the decision byte.
        let no = encode_reply(&req, false, Some("wrong_action"), &app, AT);
        let mut t = base45_decode(&no[REPLY_PREFIX.len()..]).unwrap();
        t[1] = DECISION_APPROVE;
        assert!(!verify_reply(&format!("{REPLY_PREFIX}{}", base45_encode(&t)), &pk, &req.id, &req.kid, &req.hash()));
        // Truncated, extended, wrong prefix, wrong version, garbage.
        assert!(!verify_reply(&qr[..qr.len() - 3], &pk, &req.id, &req.kid, &req.hash()));
        assert!(!verify_reply(&format!("{qr}000"), &pk, &req.id, &req.kid, &req.hash()));
        assert!(!verify_reply(&qr.replacen("PA1:", "PA2:", 1), &pk, &req.id, &req.kid, &req.hash()));
        let mut t = raw.clone(); t[0] = 2;
        assert!(!verify_reply(&format!("{REPLY_PREFIX}{}", base45_encode(&t)), &pk, &req.id, &req.kid, &req.hash()));
        assert!(!verify_reply("PA1:hello", &pk, &req.id, &req.kid, &req.hash()));
    }

    #[test]
    fn compact_reply_wrong_pinned_key_fails() {
        let (req, _) = demo_req();
        let (app, impostor) = (SigningKey::from_bytes(&[7u8; 32]), SigningKey::from_bytes(&[9u8; 32]));
        let fake = encode_reply(&req, true, None, &impostor, AT);
        assert!(!verify_reply(&fake, &app.verifying_key(), &req.id, &req.kid, &req.hash()));
        assert!(decode_reply(&fake, &app.verifying_key(), &req.id, &req.kid, &req.hash()).is_none());
    }

    #[test]
    fn compact_reply_wrong_request_fails() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let pk = app.verifying_key();
        let qr = encode_reply(&req, true, None, &app, AT);
        // Wrong action hash: only the full hash, never sent, is bound in the signature.
        let other = hex::encode(Sha256::digest(b"some other action"));
        assert!(!verify_reply(&qr, &pk, &req.id, &req.kid, &other));
        let mut h = req.hash().into_bytes(); h[63] = if h[63] == b'0' { b'1' } else { b'0' };
        assert!(!verify_reply(&qr, &pk, &req.id, &req.kid, std::str::from_utf8(&h).unwrap()), "last hash byte changed");
        // Same 8-byte id prefix, different tail: the full id is signed.
        let id2 = format!("{}{}", &req.id[..16], "ffffffffffffffff");
        assert!(!verify_reply(&qr, &pk, &id2, &req.kid, &req.hash()));
        // Different id prefix.
        assert!(!verify_reply(&qr, &pk, &"0".repeat(32), &req.kid, &req.hash()));
        // Different agent kid.
        assert!(!verify_reply(&qr, &pk, &req.id, &kid(&agent_sk(3).verifying_key()), &req.hash()));
        // Malformed expectations never verify.
        assert!(!verify_reply(&qr, &pk, "xyz", &req.kid, &req.hash()));
    }

    // ---- Review findings (Oct 17, 2026). Each test guards a fix, or pins a known gap. ----

    #[test]
    fn display_text_is_an_allowlist() {
        let (req, sk) = demo_req();
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
        let (mut req, _) = demo_req();
        let now = 1_800_000_000;
        req.exp = now + 600;
        assert!(check_time(&req, now).is_ok());
        req.exp = now;
        assert!(matches!(check_time(&req, now), Err(Reject::Expired)));
        req.exp = 4_102_444_800; // year 2100
        assert!(matches!(check_time(&req, now), Err(Reject::TooFarAhead)));
    }

    #[test]
    fn high_impact_comes_from_the_parsed_action() {
        assert!(is_elevated(&ActionView::Known { verb: "Merge", object: String::new(), target: String::new(), detail: String::new() }));
        assert!(!is_elevated(&ActionView::Known { verb: "Run", object: String::new(), target: String::new(), detail: String::new() }));
        assert!(is_elevated(&ActionView::Unknown { tool: "ci.run".into() }), "unknown tools are always high impact");
    }

    #[test]
    fn reply_sizes() {
        let (req, _) = demo_req();
        let app = SigningKey::from_bytes(&[7u8; 32]);
        let ok = encode_reply(&req, true, None, &app, AT);
        let no = encode_reply(&req, false, Some("unrecognized"), &app, AT);
        let raw = |q: &str| base45_decode(&q[REPLY_PREFIX.len()..]).unwrap().len();
        println!("approve reply {} chars ({} bytes packed), deny reply {} chars ({} bytes packed); was 416 and 444", ok.len(), raw(&ok), no.len(), raw(&no));
        assert!(raw(&ok) <= 90 && raw(&no) <= 90, "packed payload must be <= 90 bytes");
        assert_eq!((raw(&ok), raw(&no)), (78, 78));
        assert_eq!((ok.len(), no.len()), (121, 121), "every reply is the same length");
        // QR size: version 5 (37x37) at medium error correction, alphanumeric mode.
        for q in [&ok, &no] {
            let code = qrcodegen::QrCode::encode_text(q, qrcodegen::QrCodeEcc::Medium).unwrap();
            assert_eq!((code.version().value(), code.size()), (5, 37));
        }
    }

    // ---- Pairing (item 10) ----

    fn agent_sk(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
    /// Fixed TEST nonce; the app always uses fresh random bytes.
    const NONCE: [u8; PAIR_NONCE_LEN] = [0x42; PAIR_NONCE_LEN];
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

        let reply = encode_paired_reply(&pk, &app, &NONCE);
        println!("paired reply {} bytes", reply.len());
        let (pinned, nonce) = verify_paired_reply(&reply, &agent.verifying_key()).expect("valid paired reply");
        assert_eq!(nonce, NONCE);
        assert_eq!(pinned, app.verifying_key(), "agent pins the Prime's app key");
        // Wrong agent: the reply names a different kid.
        assert!(verify_paired_reply(&reply, &agent_sk(2).verifying_key()).is_none());

        // After pinning, a reply signed by any other app key must fail.
        let (req, _) = demo_req();
        let impostor = agent_sk(9);
        let fake = encode_reply(&req, true, None, &impostor, AT);
        assert!(!verify_reply(&fake, &pinned, &req.id, &req.kid, &req.hash()));
        let real = encode_reply(&req, true, None, &app, AT);
        assert!(verify_reply(&real, &pinned, &req.id, &req.kid, &req.hash()));
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
        let reply = encode_paired_reply(&agent_sk(1).verifying_key(), &agent_sk(7), &NONCE);
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
        let code = pairing_code(&a, &p, &NONCE);
        assert_eq!(code.len(), 29);
        assert_eq!(code.split(' ').count(), 6);
        assert!(code.split(' ').all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))));
        // The agent computes it from its own key and the pinned app key from the paired reply.
        let reply = encode_paired_reply(&a, &agent_sk(7), &NONCE);
        let (pinned, nonce) = verify_paired_reply(&reply, &a).unwrap();
        assert_eq!(pairing_code(&a, &pinned, &nonce), code);
        assert_ne!(pairing_code(&agent_sk(2).verifying_key(), &p, &NONCE), code, "agent key swapped");
        assert_ne!(pairing_code(&a, &agent_sk(8).verifying_key(), &NONCE), code, "app key swapped");
        assert_ne!(pairing_code(&p, &a, &NONCE), code, "order matters");
        assert_ne!(pairing_code(&a, &p, &[0x43; PAIR_NONCE_LEN]), code, "nonce changed");
        println!("pairing code {code}");
    }

    // ---- Pairing nonce (item 17) ----

    /// Pairing code test vector: agent seed [1; 32], app seed [7; 32], nonce [0x42; 16].
    #[test]
    fn pairing_code_mixes_the_primes_nonce() {
        let (a, app) = (agent_sk(1).verifying_key(), agent_sk(7));
        let code = pairing_code(&a, &app.verifying_key(), &NONCE);
        let raw = Sha256::digest([&b"prime-approve pair v2"[..], a.as_bytes(), app.verifying_key().as_bytes(), &NONCE].concat());
        assert_eq!(code.replace(' ', ""), hex::encode_upper(&raw[..12]));
        // Same two keys, a fresh nonce: a different code, so a code seen at one pairing is no good at the next.
        let r1 = encode_paired_reply(&a, &app, &[1; PAIR_NONCE_LEN]);
        let r2 = encode_paired_reply(&a, &app, &[2; PAIR_NONCE_LEN]);
        let (k1, n1) = verify_paired_reply(&r1, &a).unwrap();
        let (k2, n2) = verify_paired_reply(&r2, &a).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(pairing_code(&a, &k1, &n1), pairing_code(&a, &k2, &n2));
        println!("pairing code vector {code}; answer {} bytes", r1.len());
    }

    #[test]
    fn paired_answer_must_be_v2_with_a_well_formed_nonce() {
        let (a, app) = (agent_sk(1).verifying_key(), agent_sk(7));
        let sign = |body: &str, prefix: &str, domain: &[u8]| {
            let sig = app.sign(&[domain, body.as_bytes()].concat());
            format!("{prefix}{}.{}", B64.encode(body), B64.encode(sig.to_bytes()))
        };
        let pk = hex::encode(app.verifying_key().as_bytes());
        let k = kid(&a);
        // A v1 answer (no nonce, old prefix and domain) is refused.
        assert!(verify_paired_reply(&sign(&format!(r#"{{"kid":"{k}","app_pk":"{pk}"}}"#), "primeapprove:paired:v1:", b"primeapprove-paired-v1\n"), &a).is_none());
        // v2 prefix but no nonce, a short nonce, upper-case hex, an extra field: refused.
        for body in [
            format!(r#"{{"kid":"{k}","app_pk":"{pk}"}}"#),
            format!(r#"{{"kid":"{k}","app_pk":"{pk}","nonce":"4242"}}"#),
            format!(r#"{{"kid":"{k}","app_pk":"{pk}","nonce":"{}"}}"#, "AB".repeat(16)),
            format!(r#"{{"kid":"{k}","app_pk":"{pk}","nonce":"{}","x":1}}"#, "42".repeat(16)),
        ] {
            assert!(verify_paired_reply(&sign(&body, PAIRED_PREFIX, PAIRED_DOMAIN), &a).is_none(), "{body}");
        }
        let ok = format!(r#"{{"kid":"{k}","app_pk":"{pk}","nonce":"{}"}}"#, "42".repeat(16));
        assert_eq!(verify_paired_reply(&sign(&ok, PAIRED_PREFIX, PAIRED_DOMAIN), &a), Some((app.verifying_key(), NONCE)));
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
