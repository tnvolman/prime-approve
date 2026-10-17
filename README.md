# Prime Approve

An offline approval app for Foundation Passport Prime (KeyOS). An AI agent asks for permission with a signed QR code; the human reads the exact request on the Prime and approves or denies; the Prime answers with a signed reply QR the agent must verify before acting. No network, no trading.

Status: simulator demo. Not yet run on hardware.

## Screenshots (KeyOS simulator)

| Home | Review | Approved reply |
|---|---|---|
| ![Home](docs/screenshots/home.png) | ![Review](docs/screenshots/review.png) | ![Approved reply](docs/screenshots/approved-reply.png) |

| Tampered | Replayed | Hidden text |
|---|---|---|
| ![Bad signature](docs/screenshots/rejected-tampered.png) | ![Already used](docs/screenshots/rejected-replayed.png) | ![Hidden characters](docs/screenshots/rejected-hidden-text.png) |

## Formats (see `src/proto.rs`)

**Request QR** `primeapprove:v1:<b64url(json)>.<b64url(ed25519 sig)>`, signature over `"primeapprove-req-v1\n" + json` (the exact received bytes).
JSON: `{id: 32 hex, kid: first 16 hex of SHA-256(agent pubkey), agent: display name, title: <=60 chars, details: <=280 chars, hash: SHA-256 hex of the exact action, exp: unix seconds}`. Whole QR <= 800 bytes.

The Prime rejects: too large, malformed, bad signature (checked against paired keys before parsing), `kid` not matching the signing key, control/bidi/zero-width characters in display text, already-answered id, expired.

**Reply QR** `primeapprove:v1r:<b64url(json)>.<b64url(sig)>`, signature over `"primeapprove-res-v1\n" + json`.
JSON: `{id, kid, decision: approve|deny, hash, app: app pubkey hex}`.

App key: Ed25519 from HKDF-SHA256(salt `prime-approve`, ikm = KeyOS app seed via `GetAppSeed`, info `app key v1`).

## Agent-side check (required)

Before acting, the agent must run the equivalent of `verify_reply`: verify the signature with the paired app public key, then require `id` = the request it issued, `kid` = its own key id, `hash` = the action it is about to run, and `decision == "approve"`. The agent must also enforce its own expiry and treat each request id as single-use.

## Security note: replay protection lives on the agent

The Prime remembers the last 512 answered request ids so it refuses obvious replays, but that list is a convenience, not the guard. Once an id ages out, the Prime would show that request again. The real protection is the agent: single-use ids and expiry, checked on the agent side. Do not rely on the device-side list.

## Build and run (simulator)

Requires the Foundation SDK 1.1.0. From this folder:

    foundation develop
    foundation sim

`tools/` holds the scripts used to drive the simulator and take screenshots with `foundation-passport-drive --sim`.

The simulator has no camera, so the demo buttons generate requests on-device using a publicly known demo agent key (sim demo only, never for real use).

## License

GPL-3.0-or-later. See `LICENSE`.
