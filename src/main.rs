mod proto;
mod theme;

use std::cell::RefCell;
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slint_keyos_platform::app_ui2;

use proto::*;

app_ui2!("Prime Approve");
security::use_api!();

const STATE_FILE: &str = "state.json";
const MAX_SEEN: usize = 512;
const MAX_RECENT: usize = 10;
const DEMO_AGENT: &str = "Cos (demo agent)";
const DEMO_TITLE: &str = "Merge PR #3 into main";
// Kept short so the demo request QR is <= 600 bytes (594 with the summary fields), well under MAX_QR:
// dense QRs are hard for a real camera. The repo is carried by the summary target.
const DEMO_DETAILS: &str = "Squash merge, delete branch.\n4 files, checks passed.";
// Security demo buttons only exist in debug (simulator) builds.
const SHOW_DEV: bool = cfg!(debug_assertions);

/// Only the title, agent, decision and time are kept. Details are never stored.
#[derive(Serialize, Deserialize, Clone)]
struct Decision {
    title: String,
    agent: String,
    approved: bool,
    at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    launches: u64,
    seen: Vec<String>,
    #[serde(default)]
    recent: Vec<Decision>,
}

struct App {
    app_key: SigningKey,
    agents: Vec<Agent>,
    demo_agent: SigningKey,
    state: State,
    current: Option<Request>,
    /// Paired (local) name of the agent that signed `current`.
    current_agent: String,
    last_good_qr: Option<String>,
    pending_reply: Option<String>,
}

fn now_secs() -> Option<u64> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn ago(at: u64) -> String {
    let Some(now) = now_secs() else { return String::new() };
    let s = now.saturating_sub(at);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86400),
    }
}

// SIM DEMO ONLY: a fixed, publicly known agent key so the demo request can be generated on-device.
fn demo_agent_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"prime-approve DEMO agent key - public, never use for real").into();
    SigningKey::from_bytes(&seed)
}

fn qr_image(data: &str) -> (slint::Image, String) {
    use qrcodegen::{QrCode, QrCodeEcc};
    // Low error correction: fewer, larger modules, which are easier for a camera to read off a screen.
    let qr = QrCode::encode_text(data, QrCodeEcc::Low).expect("fits in a QR");
    let border = 2;
    let n = qr.size() + border * 2;
    let scale = (284 / n).max(1);
    let px = (n * scale) as u32;
    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(px, px);
    let w = px as usize;
    for (i, p) in buf.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = ((i % w) as i32 / scale - border, (i / w) as i32 / scale - border);
        let v = if qr.get_module(x, y) { 0 } else { 255 };
        *p = slint::Rgb8Pixel { r: v, g: v, b: v };
    }
    let info = format!("{} bytes · QR version {} · low error correction", data.len(), qr.version().value());
    (slint::Image::from_rgb8(buf), info)
}

fn save(cx: &AppContext, st: &State) {
    let data = serde_json::to_vec(st).unwrap();
    if let Err(e) = cx.fs.durable_file_write(STATE_FILE, slint_keyos_platform::fs::Location::AppData, &data) {
        log::error!("state save failed: {e:?}");
    }
}

fn load(cx: &AppContext) -> State {
    cx.fs.durable_file_read(STATE_FILE, slint_keyos_platform::fs::Location::AppData).ok().and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default()
}

fn show_error(ui: &AppWindow, title: &str, body: &str, next: &str) {
    ui.set_error_title(title.into());
    ui.set_error_body(body.into());
    ui.set_error_next(next.into());
    ui.set_page(3);
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    theme::init(&ui);
    ui.set_show_dev(SHOW_DEV);

    let seed = match Security::default().app_seed() {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            log::error!("GetAppSeed denied: {e:?}");
            show_error(&ui, "No app key", "The app key permission was denied, so this app can't sign anything.", "Allow it in Settings, then reopen Prime Approve.");
            ui.run().expect("UI running");
            return;
        }
    };
    // HKDF-SHA256 over the app seed so the signing key is only ever used for Prime Approve replies.
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(b"prime-approve"), &seed).expand(b"app key v1", &mut okm).expect("32-byte okm");
    let app_key = SigningKey::from_bytes(&okm);

    let mut state = load(&cx);
    state.launches += 1;
    save(&cx, &state);
    log::info!("launch #{} with {} seen request IDs (storage test)", state.launches, state.seen.len());

    let demo_agent = demo_agent_key();
    let agents = vec![Agent::new(DEMO_AGENT, demo_agent.verifying_key())];
    let app = Rc::new(RefCell::new(App { app_key, agents, demo_agent, state, current: None, current_agent: String::new(), last_good_qr: None, pending_reply: None }));

    let refresh_home = {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let ui = ui.unwrap();
            let a = app.borrow();
            ui.set_has_agent(!a.agents.is_empty());
            if let Some(ag) = a.agents.first() {
                ui.set_agent_name(ag.name.clone().into());
                ui.set_agent_fp(fingerprint(&ag.key).into());
            }
            let rows: Vec<Recent> = a.state.recent.iter().rev().map(|d| Recent {
                title: d.title.clone().into(), agent: d.agent.clone().into(), approved: d.approved, when: ago(d.at).into(),
            }).collect();
            ui.set_recents(slint::ModelRc::new(slint::VecModel::from(rows)));
            ui.set_app_key_line(format!("Launch #{} · {} IDs used · app key {}", a.state.launches, a.state.seen.len(), fingerprint(&a.app_key.verifying_key())).into());
            ui.set_page(0);
        }
    };
    refresh_home();

    // Live countdown on the Review screen; an expired request is pulled off the screen.
    let tick = slint::Timer::default();
    {
        let ui = ui.as_weak();
        let app = app.clone();
        tick.start(slint::TimerMode::Repeated, std::time::Duration::from_secs(1), move || {
            let ui = ui.unwrap();
            if ui.get_page() != 1 { return; }
            let mut a = app.borrow_mut();
            let (Some(r), Some(now)) = (a.current.as_ref(), now_secs()) else { return };
            if r.exp <= now {
                a.current = None;
                show_error(&ui, "Expired", "This request ran out of time before it was answered.", "Ask your agent for a fresh request.");
            } else {
                let left = r.exp - now;
                ui.set_expires_line(format!("Expires in {}:{:02}", left / 60, left % 60).into());
            }
        });
    }

    let handle_scan = {
        let ui = ui.as_weak();
        let app = app.clone();
        move |qr: String| {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            // Show the PAIRED name (set locally at pairing), never the agent-supplied `agent` string,
            // because the band sits inside the trusted frame.
            let res = decode_request(&qr, &a.agents).map(|(r, ag)| (r, ag.name.clone())).and_then(|(r, name)| {
                if a.state.seen.contains(&r.id) { return Err(Reject::AlreadyUsed); }
                if let Some(now) = now_secs() { if r.exp <= now { return Err(Reject::Expired); } }
                Ok((r, name))
            });
            match res {
                Ok((r, paired_name)) => {
                    let exp = match now_secs() { Some(now) => { let l = r.exp - now; format!("Expires in {}:{:02}", l / 60, l % 60) } None => "Expiry checked by agent".into() };
                    ui.set_agent_name(paired_name.clone().into());
                    ui.set_summary_line(summary_line(&r).unwrap_or_default().into());
                    ui.set_elevated(r.risk == "elevated");
                    ui.set_req_title(r.title.clone().into());
                    ui.set_req_details(r.details.clone().into());
                    ui.set_action_code(action_code(&r.hash).into());
                    let g: Vec<Glyph> = glyphs(&r.hash).into_iter().map(|(c, sh)| { let (r_, g_, b_) = GLYPH_RGB[c as usize]; Glyph { color: slint::Color::from_rgb_u8(r_, g_, b_), shape: sh as i32 } }).collect();
                    ui.set_glyphs(slint::ModelRc::new(slint::VecModel::from(g)));
                    ui.set_expires_line(exp.into());
                    ui.set_read_to_end(false);
                    a.last_good_qr = Some(qr);
                    a.current = Some(r);
                    a.current_agent = paired_name;
                    ui.set_page(1);
                }
                Err(e) => {
                    log::info!("rejected request: {e:?}");
                    let (t, b, n) = match e {
                        Reject::TooLarge(n) => ("Too large to read", format!("This request is {n} bytes; the limit is {MAX_QR}."), "Ask your agent to send a shorter request."),
                        Reject::Malformed(m) => ("Unreadable request", format!("Something in the request is wrong: {m}."), "Ask your agent to send a new request."),
                        Reject::UnknownAgent => ("Unknown agent", "The request names a different agent than the one that signed it.".to_string(), "Don't act on it. Check which agent sent this."),
                        Reject::UnsafeText => ("Hidden characters", "The request has invisible or text-reordering characters, so it can't be shown honestly.".to_string(), "Ask your agent to send a new request."),
                        Reject::BadSignature => ("Bad signature", "The request was changed after your agent signed it, or it didn't come from a paired agent.".to_string(), "Ask your agent to send a new request."),
                        Reject::AlreadyUsed => ("Already used", "This request was already answered. Each request can be answered once.".to_string(), "If you still need this, ask for a fresh request."),
                        Reject::Expired => ("Expired", "This request ran out of time before it was answered.".to_string(), "Ask for a fresh request."),
                    };
                    show_error(&ui, t, &b, n);
                }
            }
        }
    };

    let make_demo = {
        let app = app.clone();
        move |title: &str| -> String {
            let a = app.borrow();
            let action = br#"{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":3,"method":"squash"}"#;
            let mut id = [0u8; 16];
            getrandom::getrandom(&mut id).expect("TRNG");
            let req = Request {
                id: hex::encode(id),
                kid: kid(&a.demo_agent.verifying_key()),
                agent: DEMO_AGENT.into(),
                title: title.into(),
                details: DEMO_DETAILS.into(),
                risk: "elevated".into(),
                hash: hex::encode(Sha256::digest(action)),
                exp: now_secs().unwrap_or(0) + 600,
                verb: Some("Merge".into()),
                object: Some("PR #3".into()),
                target: Some("typewright-website-audit".into()),
            };
            encode_request(&req, &a.demo_agent)
        }
    };

    let cb = ui.global::<Callbacks>();
    // Validly signed, but the title carries a right-to-left override that would visually reorder it.
    { let h = handle_scan.clone(); let m = make_demo.clone(); cb.on_scan_hidden(move || h(m("Merge PR #3 \u{202E}tfard sa evas"))); }
    { let h = handle_scan.clone(); let m = make_demo.clone(); cb.on_scan_demo(move || h(m(DEMO_TITLE))); }
    { let h = handle_scan.clone(); let m = make_demo.clone(); cb.on_scan_tampered(move || {
        let qr = m(DEMO_TITLE);
        let (head, sig) = qr.rsplit_once('.').unwrap();
        // Flip one character of the signed body: the signature must no longer verify.
        let mut b: Vec<char> = head.chars().collect();
        let i = REQ_PREFIX.len() + 30;
        b[i] = if b[i] == 'A' { 'B' } else { 'A' };
        h(format!("{}.{}", b.into_iter().collect::<String>(), sig));
    }); }
    { let h = handle_scan.clone(); let app = app.clone(); let ui_w = ui.as_weak(); cb.on_scan_replay(move || {
        let last = app.borrow().last_good_qr.clone();
        match last { Some(q) => h(q), None => show_error(&ui_w.unwrap(), "Nothing to replay yet", "Answer a demo request first.", "Then try replaying it.") }
    }); }

    // Signs the reply, records the decision, and returns the reply QR text.
    let decide = {
        let ui = ui.as_weak();
        let app = app.clone();
        let cx = cx.clone();
        move |approve: bool, reason: Option<&str>| -> bool {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            let Some(req) = a.current.take() else { return false };
            a.state.seen.push(req.id.clone());
            if a.state.seen.len() > MAX_SEEN { a.state.seen.remove(0); }
            let agent = std::mem::take(&mut a.current_agent);
            a.state.recent.push(Decision { title: req.title.clone(), agent, approved: approve, at: now_secs().unwrap_or(0) });
            if a.state.recent.len() > MAX_RECENT { a.state.recent.remove(0); }
            save(&cx, &a.state);
            let reply = encode_reply(&req, approve, reason, &a.app_key);
            let ok = verify_reply(&reply, &a.app_key.verifying_key(), &req.id, &req.kid, &req.hash);
            log::info!("reply {} bytes, decision={}, reason={reason:?}, agent-side verify(approve)={ok}", reply.len(), if approve {"approve"} else {"deny"});
            let (img, info) = qr_image(&reply);
            ui.set_reply_qr(img);
            ui.set_qr_line(info.into());
            ui.set_approved(approve);
            a.pending_reply = Some(reply);
            true
        }
    };
    { let d = decide.clone(); let ui = ui.as_weak(); cb.on_approve(move || { if d(true, None) { ui.unwrap().set_page(2); } }); }
    { let ui = ui.as_weak(); cb.on_deny(move || ui.unwrap().set_page(4)); }
    { let d = decide.clone(); let ui = ui.as_weak(); cb.on_deny_with(move |r| {
        let ui = ui.unwrap();
        let reason = if r.is_empty() { None } else { Some(r.as_str()) };
        if d(false, reason) { ui.set_page(if r == "unrecognized" { 5 } else { 2 }); }
    }); }
    { let app = app.clone(); let ui = ui.as_weak(); cb.on_unpair(move |yes| {
        let ui = ui.unwrap();
        if yes { app.borrow_mut().agents.clear(); log::info!("agent unpaired"); }
        ui.set_page(2);
    }); }
    { let r = refresh_home.clone(); cb.on_done(move || r()); }

    ui.run().expect("UI running");
    drop(tick);
}
