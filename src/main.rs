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
const DEMO_TITLE: &str = "Merge PR #3 in typewright-website-audit";

#[derive(Serialize, Deserialize, Default)]
struct State {
    launches: u64,
    seen: Vec<String>,
}

struct App {
    app_key: SigningKey,
    agents: Vec<Agent>,
    demo_agent: SigningKey,
    state: State,
    current: Option<Request>,
    last_good_qr: Option<String>,
}

fn now_secs() -> Option<u64> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

// SIM DEMO ONLY: a fixed, publicly known agent key so the demo request can be generated on-device.
fn demo_agent_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"prime-approve DEMO agent key - public, never use for real").into();
    SigningKey::from_bytes(&seed)
}

fn qr_image(data: &str) -> (slint::Image, String) {
    use qrcodegen::{QrCode, QrCodeEcc};
    let qr = QrCode::encode_text(data, QrCodeEcc::Medium).expect("fits in a QR");
    let border = 2;
    let n = qr.size() + border * 2;
    let scale = (284 / n).max(1);
    let px = (n * scale) as u32;
    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(px, px);
    let w = px as usize;
    for (i, p) in buf.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = ((i % w) as i32 / scale - border, (i / w) as i32 / scale - border);
        let dark = qr.get_module(x, y);
        let v = if dark { 0 } else { 255 };
        *p = slint::Rgb8Pixel { r: v, g: v, b: v };
    }
    let info = format!("{} bytes · QR version {} ({}×{} modules) · medium error correction", data.len(), qr.version().value(), qr.size(), qr.size());
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

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    theme::init(&ui);

    let seed = match Security::default().app_seed() {
        Ok(s) => *s.as_bytes(),
        Err(e) => {
            log::error!("GetAppSeed denied: {e:?}");
            ui.set_page(3);
            ui.set_error_title("No app key".into());
            ui.set_error_body("The app seed permission was denied, so this app cannot sign anything.".into());
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
    let agents = vec![Agent::new("Cos (demo agent)", demo_agent.verifying_key())];
    let app = Rc::new(RefCell::new(App { app_key, agents, demo_agent, state, current: None, last_good_qr: None }));

    let refresh_home = {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let ui = ui.unwrap();
            let a = app.borrow();
            let lines: Vec<String> = a.agents.iter().map(|ag| format!("{}\nfingerprint {}", ag.name, fingerprint(&ag.key))).collect();
            ui.set_paired_line(lines.join("\n").into());
            ui.set_status_line(format!("Launch #{} · {} IDs used\nApp key {}", a.state.launches, a.state.seen.len(), fingerprint(&a.app_key.verifying_key())).into());
            ui.set_page(0);
        }
    };
    refresh_home();

    let handle_scan = {
        let ui = ui.as_weak();
        let app = app.clone();
        move |qr: String| {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            let res = decode_request(&qr, &a.agents).map(|(r, _)| r).and_then(|r| {
                if a.state.seen.contains(&r.id) { return Err(Reject::AlreadyUsed); }
                if let Some(now) = now_secs() { if r.exp <= now { return Err(Reject::Expired); } }
                Ok(r)
            });
            match res {
                Ok(r) => {
                    let exp = match now_secs() { Some(now) => format!("expires in {} min", (r.exp - now) / 60), None => "expiry checked by agent".into() };
                    ui.set_agent_line(format!("From {} (paired)", r.agent).into());
                    ui.set_req_title(r.title.clone().into());
                    ui.set_req_details(r.details.clone().into());
                    ui.set_hash_line(format!("Action hash {} · compare with the agent's screen", &r.hash[..8]).into());
                    ui.set_meta_line(exp.into());
                    ui.set_read_to_end(false);
                    a.last_good_qr = Some(qr);
                    a.current = Some(r);
                    ui.set_page(1);
                }
                Err(e) => {
                    log::info!("rejected request: {e:?}");
                    let (t, b) = match e {
                        Reject::TooLarge(n) => ("Too large to read", format!("This request is {n} bytes; the limit is {MAX_QR}.")),
                        Reject::Malformed(m) => ("Unreadable request", format!("The request is malformed: {m}.")),
                        Reject::UnknownAgent => ("Unknown agent", "The request names a key that is not the one that signed it.".to_string()),
                        Reject::UnsafeText => ("Hidden characters", "The request contains invisible or text-reordering characters, so it cannot be shown honestly.".to_string()),
                        Reject::BadSignature => ("Bad signature", "The request was changed after the agent signed it, or it was not signed by a paired agent.".to_string()),
                        Reject::AlreadyUsed => ("Already used", "This request ID was already answered. A request can only be answered once.".to_string()),
                        Reject::Expired => ("Expired", "This request has expired. Ask the agent for a new one.".to_string()),
                    };
                    ui.set_error_title(t.into());
                    ui.set_error_body(b.into());
                    ui.set_page(3);
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
                agent: "Cos (demo agent)".into(),
                title: title.into(),
                details: "Squash-merge pull request #3 into main of tnvolman/typewright-website-audit. This deletes the branch afterwards. This is a demo request generated inside the simulator to exercise the review flow, including the rule that approval stays locked until you have read every line.".into(),
                hash: hex::encode(Sha256::digest(action)),
                exp: now_secs().unwrap_or(0) + 600,
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
        match last { Some(q) => h(q), None => { let ui = ui_w.unwrap(); ui.set_error_title("Nothing to replay yet".into()); ui.set_error_body("Answer a demo request first, then try replaying it.".into()); ui.set_page(3); } }
    }); }

    let decide = {
        let ui = ui.as_weak();
        let app = app.clone();
        let cx = cx.clone();
        move |approve: bool| {
            let ui = ui.unwrap();
            let mut a = app.borrow_mut();
            let Some(req) = a.current.take() else { return };
            a.state.seen.push(req.id.clone());
            if a.state.seen.len() > MAX_SEEN { a.state.seen.remove(0); }
            save(&cx, &a.state);
            let reply = encode_reply(&req, approve, &a.app_key);
            let ok = verify_reply(&reply, &a.app_key.verifying_key(), &req.id, &req.kid, &req.hash);
            log::info!("reply {} bytes, decision={}, agent-side verify(approve)={ok}", reply.len(), if approve {"approve"} else {"deny"});
            let (img, info) = qr_image(&reply);
            ui.set_reply_qr(img);
            ui.set_qr_line(format!("Show this to the agent to scan. {info}").into());
            ui.set_result_line(if approve { "Approved and signed" } else { "Denied and signed" }.into());
            ui.set_page(2);
        }
    };
    { let d = decide.clone(); cb.on_approve(move || d(true)); }
    { let d = decide.clone(); cb.on_deny(move || d(false)); }
    { let r = refresh_home.clone(); cb.on_done(move || r()); }

    ui.run().expect("UI running");
}
