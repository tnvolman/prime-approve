// SPDX-FileCopyrightText: 2026 Michael McClanahan
// SPDX-License-Identifier: GPL-3.0-or-later

mod proto;
mod theme;

use std::cell::RefCell;
use std::rc::Rc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slint_keyos_platform::app_ui2;

use proto::*;

app_ui2!("Prime Approve");
security::use_api!();

const STATE_FILE: &str = "state.json";
const MAX_SEEN: usize = 512;
const MAX_RECENT: usize = 10;
/// Prime screen width in px; the reply QR is drawn across all of it.
const SCREEN_W: i32 = 480;
/// Demo mode: built only with `--features demo`. It pairs a demo agent whose private key is public
/// (anyone can sign as it), so a demo build shows a "Demo key, not secure" banner on every screen.
/// A default build has no demo key, no demo agent and no demo buttons.
const DEMO: bool = cfg!(feature = "demo");
#[cfg(feature = "demo")]
const DEMO_AGENT: &str = "Cos (demo agent)";
#[cfg(feature = "demo")]
const DEMO_TITLE: &str = "Merge PR #2 into main";
// A real, already-merged PR (tnvolman/typewright-website-audit #2), pinned to its head commit.
// Kept short so the demo request QR stays <= 600 bytes: dense QRs are hard for a real camera.
#[cfg(feature = "demo")]
const DEMO_DETAILS: &str = "Squash merge at 33393c6.\n10 files changed.";
// Security demo buttons (tampered, replay, hidden text) need a demo build AND a debug build.
const SHOW_DEV: bool = DEMO && cfg!(debug_assertions);

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
    #[serde(default)]
    agents: Vec<Paired>,
}

fn pk_of(p: &Paired) -> Option<VerifyingKey> {
    let b: [u8; 32] = hex::decode(&p.pk).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&b).ok()
}

struct App {
    /// None until the boot timer has fetched the app seed (it can only be fetched once the event loop runs).
    app_key: Option<SigningKey>,
    agents: Vec<Agent>,
    #[cfg(feature = "demo")]
    demo_agent: SigningKey,
    state: State,
    current: Option<Request>,
    /// Paired (local) name of the agent that signed `current`.
    current_agent: String,
    /// Key of the agent that signed `current` (offered for unpairing after "Don't recognize this").
    current_key: Option<VerifyingKey>,
    /// Agent key waiting on the pair-confirm screen.
    pending_pair: Option<VerifyingKey>,
    /// Pairing shown on the answer screen, waiting for "Codes match". Memory only: never saved until
    /// confirmed, and dropped if the screen is left any other way or the app relaunches.
    pair_answer: Option<PendingPair>,
    /// Agent the unpair prompt is about, and the page to return to afterwards.
    unpair_target: Option<VerifyingKey>,
    unpair_return: i32,
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

// DEMO BUILDS ONLY: a fixed, publicly known agent key so the demo request can be generated on-device.
#[cfg(feature = "demo")]
fn demo_agent_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"prime-approve DEMO agent key - public, never use for real").into();
    SigningKey::from_bytes(&seed)
}

/// Renders a QR as a pixel-exact image `target` px wide or less, with a 2-module quiet zone.
fn qr_image(data: &str, ecc: qrcodegen::QrCodeEcc, target: i32) -> (slint::Image, String) {
    use qrcodegen::{QrCode, QrCodeEcc};
    let qr = QrCode::encode_text(data, ecc).expect("fits in a QR");
    let border = 2;
    let n = qr.size() + border * 2;
    let scale = (target / n).max(1);
    let px = (n * scale) as u32;
    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(px, px);
    let w = px as usize;
    for (i, p) in buf.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = ((i % w) as i32 / scale - border, (i / w) as i32 / scale - border);
        let v = if qr.get_module(x, y) { 0 } else { 255 };
        *p = slint::Rgb8Pixel { r: v, g: v, b: v };
    }
    let level = match ecc { QrCodeEcc::Low => "low", QrCodeEcc::Medium => "medium", QrCodeEcc::Quartile => "quartile", QrCodeEcc::High => "high" };
    let info = format!("{} chars · QR version {} ({}×{}) · {level} error correction", data.len(), qr.version().value(), qr.size(), qr.size());
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

/// Rebuilds the in-memory agent list: saved pairings, plus the demo agent in demo builds
/// (memory only, never saved, so it can't outlive a demo build).
fn rebuild_agents(a: &mut App) {
    let mut v: Vec<Agent> = a.state.agents.iter().filter_map(|p| pk_of(p).map(|k| Agent::new(&p.name, k))).collect();
    #[cfg(feature = "demo")]
    if !v.iter().any(|x| x.key == a.demo_agent.verifying_key()) {
        v.insert(0, Agent::new(DEMO_AGENT, a.demo_agent.verifying_key()));
    }
    a.agents = v;
}

/// Pairing code split over two lines for the screen: "XXXX XXXX XXXX\nXXXX XXXX XXXX".
fn code_two_lines(code: &str) -> String {
    let g: Vec<&str> = code.split(' ').collect();
    format!("{}\n{}", g[..3].join(" "), g[3..].join(" "))
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

    let mut state = load(&cx);
    state.launches += 1;
    save(&cx, &state);
    log::info!("launch #{} with {} seen request IDs (storage test)", state.launches, state.seen.len());

    log::info!("{} saved agent pairing(s)", state.agents.len());
    ui.set_demo_mode(DEMO);
    #[cfg(feature = "demo")]
    let demo_agent = demo_agent_key();
    let app = Rc::new(RefCell::new(App {
        app_key: None, agents: Vec::new(),
        #[cfg(feature = "demo")]
        demo_agent,
        state, current: None, current_agent: String::new(), current_key: None, last_good_qr: None, pending_reply: None,
        pending_pair: None, pair_answer: None, unpair_target: None, unpair_return: 0,
    }));
    rebuild_agents(&mut app.borrow_mut());

    let refresh_home = {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let ui = ui.unwrap();
            // Home is reached from every exit; an unconfirmed pairing never survives it.
            app.borrow_mut().pair_answer = None;
            let a = app.borrow();
            ui.set_has_agent(!a.agents.is_empty());
            let rows: Vec<AgentRow> = a.agents.iter().map(|ag| AgentRow { name: ag.name.clone().into(), fp: fingerprint(&ag.key).into() }).collect();
            ui.set_agents(slint::ModelRc::new(slint::VecModel::from(rows)));
            let rows: Vec<Recent> = a.state.recent.iter().rev().map(|d| Recent {
                title: d.title.clone().into(), agent: d.agent.clone().into(), approved: d.approved, when: ago(d.at).into(),
            }).collect();
            ui.set_recents(slint::ModelRc::new(slint::VecModel::from(rows)));
            let key = a.app_key.as_ref().map(|k| fingerprint(&k.verifying_key())).unwrap_or_else(|| "loading".into());
            ui.set_app_key_line(format!("Launch #{} · {} IDs used · app key {}", a.state.launches, a.state.seen.len(), key).into());
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

    let handle_request = {
        let ui = ui.as_weak();
        let app = app.clone();
        move |qr: String| {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            // Show the PAIRED name (set locally at pairing), never the agent-supplied `agent` string,
            // because the band sits inside the trusted frame.
            let res = decode_request(&qr, &a.agents).map(|(r, ag)| (r, ag.name.clone(), ag.key)).and_then(|(r, name, key)| {
                if a.state.seen.contains(&r.id) { return Err(Reject::AlreadyUsed); }
                if let Some(now) = now_secs() { check_time(&r, now)?; }
                Ok((r, name, key))
            });
            match res {
                Ok((r, paired_name, key)) => {
                    let exp = match now_secs() { Some(now) => { let l = r.exp - now; format!("Expires in {}:{:02}", l / 60, l % 60) } None => "Expiry checked by agent".into() };
                    ui.set_agent_name(paired_name.clone().into());
                    ui.set_summary_line(summary_line(&r).unwrap_or_default().into());
                    ui.set_elevated(is_elevated(&r));
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
                    a.current_key = Some(key);
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
                        Reject::TooFarAhead => ("Expiry too long", format!("This request stays valid for more than {} minutes. Requests must be short-lived.", MAX_LIFETIME_SECS / 60), "Ask your agent to send a new request."),
                    };
                    show_error(&ui, t, &b, n);
                }
            }
        }
    };

    // A pairing offer: check it, then ask the person to name and confirm the agent.
    let handle_pair = {
        let ui = ui.as_weak();
        let app = app.clone();
        move |qr: String| {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            let Some(app_pk) = a.app_key.as_ref().map(|k| k.verifying_key()) else {
                show_error(&ui, "App key not ready", "The app key hasn't loaded yet, so this Prime can't pair.", "Try again in a moment.");
                return;
            };
            match decode_pair_offer(&qr, now_secs()) {
                Ok(pk) => {
                    let hexpk = hex::encode(pk.as_bytes());
                    let existing = a.state.agents.iter().find(|p| p.pk == hexpk).map(|p| p.name.clone());
                    if existing.is_none() && a.state.agents.len() >= MAX_AGENTS {
                        show_error(&ui, "Too many agents", &format!("This Prime already has {MAX_AGENTS} paired agents."), "Unpair one from the home screen, then scan again.");
                        return;
                    }
                    ui.set_pair_repair(existing.is_some());
                    ui.set_pair_name(existing.unwrap_or_default().into());
                    ui.set_pair_default(format!("Agent {}", a.state.agents.len() + 1).into());
                    ui.set_pair_error("".into());
                    ui.set_pair_fp(fingerprint(&pk).into());
                    ui.set_pair_code(code_two_lines(&pairing_code(&pk, &app_pk)).into());
                    a.pending_pair = Some(pk);
                    ui.set_page(6);
                }
                Err(e) => {
                    log::info!("rejected pairing offer: {e:?}");
                    let (t, b) = match e {
                        Reject::TooLarge(n) => ("Too large to read", format!("This pairing code is {n} bytes; the limit is {MAX_QR}.")),
                        Reject::BadSignature => ("Bad signature", "The pairing code wasn't signed by the key it offers.".to_string()),
                        Reject::Expired => ("Expired", "This pairing code ran out of time.".to_string()),
                        Reject::TooFarAhead => ("Expiry too long", format!("Pairing codes must expire within {} minutes.", MAX_LIFETIME_SECS / 60)),
                        _ => ("Unreadable pairing code", "Something in the pairing code is wrong.".to_string()),
                    };
                    show_error(&ui, t, &b, "Ask your agent for a new pairing code.");
                }
            }
        }
    };

    // Every scanned text goes through here: Scan button, Launcher handoff and demo buttons.
    let handle_scan = {
        let hr = handle_request.clone();
        let hp = handle_pair.clone();
        move |qr: String| {
            if qr.starts_with(PAIR_PREFIX) { hp(qr) } else { hr(qr) }
        }
    };

    let cb = ui.global::<Callbacks>();

    // Real intake: open the system QR scanner. Only plain-text QRs are accepted; everything still goes
    // through handle_scan (signature, pairing, text, expiry and replay checks).
    {
        let h = handle_scan.clone();
        let ui_w = ui.as_weak();
        cb.on_scan_request(move || {
            let h = h.clone();
            let ui_w = ui_w.clone();
            slint_keyos_platform::spawn_local(async move {
                use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
                let opts = ScanQrOptions {
                    header_title: "Scan".into(),
                    message: "Point the camera at your agent's request or pairing code.".into(),
                    ..Default::default()
                };
                match slint_keyos_platform::navigation::async_open_qr_scanner::<gui_permissions::GuiPermissions>(opts).await {
                    Ok(Some(ScanQrResult::Qr { data, .. })) => match String::from_utf8(data) {
                        Ok(text) => h(text),
                        Err(_) => show_error(&ui_w.unwrap(), "Not a Prime Approve request", "That code isn't text.", "Scan the code your agent shows."),
                    },
                    Ok(Some(ScanQrResult::Ur2 { .. })) => show_error(&ui_w.unwrap(), "Not a Prime Approve request", "That looks like a wallet code, not an agent request.", "Scan the code your agent shows."),
                    Ok(_) => {} // Closed without scanning: stay where we were.
                    Err(e) => {
                        log::error!("QR scanner failed: {e:?}");
                        show_error(&ui_w.unwrap(), "Camera unavailable", "The QR scanner couldn't open.", "Try again in a moment.");
                    }
                }
            }).detach();
        });
    }

    #[cfg(feature = "demo")]
    {
        let make_demo = {
            let app = app.clone();
            move |title: &str| -> String {
                let a = app.borrow();
                let mut id = [0u8; 16];
                getrandom::getrandom(&mut id).expect("TRNG");
                let req = Request {
                    id: hex::encode(id),
                    kid: kid(&a.demo_agent.verifying_key()),
                    agent: DEMO_AGENT.into(),
                    title: title.into(),
                    details: DEMO_DETAILS.into(),
                    risk: "elevated".into(),
                    hash: hex::encode(Sha256::digest(DEMO_ACTION)),
                    exp: now_secs().unwrap_or(0) + 600,
                    verb: Some("Merge".into()),
                    object: Some("PR #2".into()),
                    target: Some("typewright-website-audit".into()),
                };
                encode_request(&req, &a.demo_agent)
            }
        };

        // Validly signed, but the title carries a right-to-left override that would visually reorder it.
        { let h = handle_scan.clone(); let m = make_demo.clone(); cb.on_scan_hidden(move || h(m("Merge PR #2 \u{202E}tfard sa evas"))); }
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
        // Demo pair: a FRESH random agent key each time, so a saved demo pairing is never a key
        // anyone else holds (unlike the fixed demo agent). Goes through the same handler as a scan.
        { let h = handle_scan.clone(); cb.on_scan_demo_pair(move || {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("TRNG");
            h(encode_pair_offer(&SigningKey::from_bytes(&seed), now_secs().unwrap_or(0) + 300));
        }); }
        { let h = handle_scan.clone(); let app = app.clone(); let ui_w = ui.as_weak(); cb.on_scan_replay(move || {
            let last = app.borrow().last_good_qr.clone();
            match last { Some(q) => h(q), None => show_error(&ui_w.unwrap(), "Nothing to replay yet", "Answer a demo request first.", "Then try replaying it.") }
        }); }
    }

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
            a.unpair_target = a.current_key.take();
            a.unpair_return = 2;
            a.state.recent.push(Decision { title: req.title.clone(), agent, approved: approve, at: now_secs().unwrap_or(0) });
            if a.state.recent.len() > MAX_RECENT { a.state.recent.remove(0); }
            save(&cx, &a.state);
            let Some(app_key) = a.app_key.clone() else { return false };
            let reply = encode_reply(&req, approve, reason, &app_key, now_secs().unwrap_or(0));
            let ok = verify_reply(&reply, &app_key.verifying_key(), &req.id, &req.kid, &req.hash);
            log::info!("reply {} bytes, decision={}, reason={reason:?}, agent-side verify(approve)={ok}", reply.len(), if approve {"approve"} else {"deny"});
            // Compact reply: medium error correction, drawn across the full screen width for a webcam.
            let (img, info) = qr_image(&reply, qrcodegen::QrCodeEcc::Medium, SCREEN_W);
            ui.set_reply_qr(img);
            ui.set_qr_line(info.into());
            ui.set_approved(approve);
            a.pending_reply = Some(reply);
            true
        }
    };
    { let d = decide.clone(); let ui = ui.as_weak(); cb.on_approve(move || { if d(true, None) { ui.unwrap().set_page(2); } }); }
    { let ui = ui.as_weak(); cb.on_deny(move || ui.unwrap().set_page(4)); }
    { let d = decide.clone(); let ui = ui.as_weak(); let app = app.clone(); cb.on_deny_with(move |r| {
        let ui = ui.unwrap();
        let reason = if r.is_empty() { None } else { Some(r.as_str()) };
        if d(false, reason) {
            let name = app.borrow().agents.iter().find(|x| Some(x.key) == app.borrow().unpair_target).map(|x| x.name.clone());
            match name {
                Some(n) if r == "unrecognized" => { ui.set_agent_name(n.into()); ui.set_page(5); }
                _ => ui.set_page(2),
            }
        }
    }); }
    // Unpair: removes the agent from saved state, so it stays unpaired after a relaunch.
    { let app = app.clone(); let ui = ui.as_weak(); let cx = cx.clone(); let refresh_home = refresh_home.clone(); cb.on_unpair(move |yes| {
        let ui = ui.unwrap();
        let back = {
            let mut a = app.borrow_mut();
            let target = a.unpair_target.take();
            if let (true, Some(k)) = (yes, target) {
                let hexpk = hex::encode(k.as_bytes());
                a.state.agents.retain(|p| p.pk != hexpk);
                save(&cx, &a.state);
                rebuild_agents(&mut a);
                // The built-in demo agent lives in memory only; drop it until the next launch.
                a.agents.retain(|x| x.key != k);
                log::info!("agent unpaired, {} saved left", a.state.agents.len());
            }
            a.unpair_return
        };
        if back == 0 { refresh_home(); } else { ui.set_page(back); }
    }); }
    // Tap a paired agent on the home screen to unpair it.
    { let app = app.clone(); let ui = ui.as_weak(); cb.on_manage_agent(move |i| {
        let ui = ui.unwrap();
        let mut a = app.borrow_mut();
        let Some((name, key)) = a.agents.get(i as usize).map(|x| (x.name.clone(), x.key)) else { return };
        a.unpair_target = Some(key);
        a.unpair_return = 0;
        ui.set_agent_name(name.into());
        ui.set_page(5);
    }); }
    // Pair: validate the person's name, then show the signed answer for the agent to scan. Nothing is
    // saved yet: the agent only learns the Prime's key (and can show the pairing code) from this answer,
    // so the pairing is saved only when the person taps "Codes match" after comparing.
    { let app = app.clone(); let ui = ui.as_weak(); cb.on_pair_confirm(move |typed| {
        let ui = ui.unwrap();
        let mut a = app.borrow_mut();
        let typed = typed.trim().to_string();
        let name = if typed.is_empty() { ui.get_pair_default().to_string() } else { typed };
        if !valid_agent_name(&name) {
            ui.set_pair_error(format!("Use 1 to {MAX_AGENT_NAME} plain letters, digits or symbols.").into());
            return;
        }
        let (Some(pk), Some(app_key)) = (a.pending_pair.take(), a.app_key.clone()) else { return };
        let hexpk = hex::encode(pk.as_bytes());
        if !a.state.agents.iter().any(|p| p.pk == hexpk) && a.state.agents.len() >= MAX_AGENTS {
            show_error(&ui, "Too many agents", &format!("This Prime already has {MAX_AGENTS} paired agents."), "Unpair one from the home screen, then scan again.");
            return;
        }
        let reply = encode_paired_reply(&pk, &app_key);
        let ok = verify_paired_reply(&reply, &pk) == Some(app_key.verifying_key());
        log::info!("pairing pending (not saved) for {}, reply {} bytes, agent-side verify={ok}", fingerprint(&pk), reply.len());
        let (img, info) = qr_image(&reply, qrcodegen::QrCodeEcc::Low, 284);
        ui.set_reply_qr(img);
        ui.set_qr_line(info.into());
        ui.set_agent_name(name.clone().into());
        a.pair_answer = Some(PendingPair { pk, name });
        ui.set_page(7);
    }); }
    // Answer screen: "Codes match" saves the pending pairing; "Don't match" throws it away.
    for answer in [PairAnswer::CodesMatch, PairAnswer::DontMatch] {
        let app = app.clone(); let ui = ui.as_weak(); let cx = cx.clone(); let r = refresh_home.clone();
        let f = move || {
            let full = {
                let mut a = app.borrow_mut();
                let pending = a.pair_answer.take();
                let out = resolve_pairing(&mut a.state.agents, pending, answer, now_secs().unwrap_or(0));
                if matches!(out, PairOutcome::Saved | PairOutcome::Renamed) {
                    save(&cx, &a.state);
                    rebuild_agents(&mut a);
                }
                log::info!("pairing answer {answer:?}: {out:?}, {} saved", a.state.agents.len());
                out == PairOutcome::Full
            };
            r();
            if full { show_error(&ui.unwrap(), "Too many agents", &format!("This Prime already has {MAX_AGENTS} paired agents."), "Unpair one from the home screen, then scan again."); }
        };
        if answer == PairAnswer::CodesMatch { cb.on_pair_match(f); } else { cb.on_pair_mismatch(f); }
    }
    { let app = app.clone(); let r = refresh_home.clone(); cb.on_pair_cancel(move || { app.borrow_mut().pending_pair = None; r(); }); }
    { let r = refresh_home.clone(); cb.on_done(move || r()); }

    // Boot step. The app seed can only be fetched once the event loop is running (fetching it before
    // `ui.run()` hangs on a dark screen), so this single-shot timer fires on the first loop turn.
    // It derives the signing key, then picks up a request handed over by the Launcher's scanner.
    let boot = slint::Timer::default();
    {
        let ui_w = ui.as_weak();
        let app = app.clone();
        let refresh_home = refresh_home.clone();
        let h = handle_scan.clone();
        let cx = cx.clone();
        boot.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(0), move || {
            let ui = ui_w.unwrap();
            let seed = match Security::default().app_seed() {
                Ok(s) => *s.as_bytes(),
                Err(e) => {
                    log::error!("GetAppSeed denied: {e:?}");
                    show_error(&ui, "No app key", "The app key permission was denied, so this app can't sign anything.", "Allow it in Settings, then reopen Prime Approve.");
                    return;
                }
            };
            // HKDF-SHA256 over the app seed so the signing key is only ever used for Prime Approve replies.
            let mut okm = [0u8; 32];
            hkdf::Hkdf::<Sha256>::new(Some(b"prime-approve"), &seed).expand(b"app key v1", &mut okm).expect("32-byte okm");
            app.borrow_mut().app_key = Some(SigningKey::from_bytes(&okm));
            refresh_home();
            // A request scanned from the Launcher arrives as a pending navigation request.
            if let Ok(Some(bytes)) = cx.gui.navigate_pending() {
                use slint_keyos_platform::gui_server_api::navigation::qrscanner::{MatchedQrResult, ScanQrResult};
                match MatchedQrResult::from_slice(&bytes).map(|m| m.scan_result) {
                    Some(ScanQrResult::Qr { data, .. }) => match String::from_utf8(data) {
                        Ok(text) => h(text),
                        Err(_) => show_error(&ui, "Not a Prime Approve request", "That code isn't text.", "Scan the code your agent shows."),
                    },
                    _ => log::info!("pending navigation request was not a text QR"),
                }
            }
        });
    }

    ui.run().expect("UI running");
    drop(tick);
    drop(boot);
}
