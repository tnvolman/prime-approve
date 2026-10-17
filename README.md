# Prime Approve

An offline approval app for Foundation Passport Prime (KeyOS). An AI agent asks for permission with a signed QR code; the human reads the exact request on the Prime and approves or denies; the Prime answers with a signed reply QR the agent must verify before acting. No network, no trading.

Status: simulator demo. Not yet run on hardware (see *Known items to test on hardware*).

## Screenshots (KeyOS simulator, color-corrected)

| Home | Review | Approved reply |
|---|---|---|
| ![Home with recent decisions](docs/screenshots/home.png) | ![Review: trusted band, request, trusted frame with summary line, action code and colored shapes](docs/screenshots/review.png) | ![Approved: signed reply QR](docs/screenshots/approved-reply.png) |

| Deny reason | Replayed | Hidden text |
|---|---|---|
| ![Why deny?](docs/screenshots/deny-reason.png) | ![Already used](docs/screenshots/rejected-replayed.png) | ![Hidden characters](docs/screenshots/rejected-hidden-text.png) |

## Formats (see `src/proto.rs`)

**Request QR** `primeapprove:v1:<b64url(json)>.<b64url(ed25519 sig)>`. The signature covers `"primeapprove-req-v1\n" + json`, the exact bytes received. The whole QR must be 800 bytes or less.

JSON fields:

| field | meaning |
|---|---|
| `id` | 32 hex chars (128-bit), single-use |
| `kid` | first 16 hex chars of SHA-256(agent public key) |
| `agent` | the agent's display name. Checked for hidden characters but **not shown in the trusted band**; the band shows the name you gave the agent when you paired it |
| `title` | 60 chars or fewer |
| `details` | 280 chars or fewer; newlines allowed |
| `risk` | `"routine"` or `"elevated"`. Anything else is rejected. Elevated (spends money, deletes, merges, sends) gets an amber "High impact" band |
| `hash` | 64 hex chars: SHA-256 of the exact action bytes the agent will run, computed by the agent |
| `exp` | expiry, unix seconds |
| `verb`, `object`, `target` | *optional, all three or none.* The structured summary (see below) |

The Prime rejects a request that is:
- too large or malformed
- badly signed (checked against paired keys before anything is parsed)
- carrying a `kid` that doesn't match the signing key
- using a `risk` value it doesn't know
- hiding control, bidi or zero-width characters in display text
- carrying an invalid summary
- already answered
- expired

It signs nothing when it rejects.

**Reply QR** `primeapprove:v1r:<b64url(json)>.<b64url(sig)>`. The signature covers `"primeapprove-res-v1\n" + json`.

JSON: `{id, kid, decision: "approve"|"deny", hash, app: app public key hex, reason?}`.

`reason` is optional and only appears on a deny: `"wrong_action"`, `"not_now"` or `"unrecognized"`. It is **never** present on an approve. Any other value is dropped, not signed. If the person chooses "Don't recognize this", the Prime also offers to unpair that agent.

**QR codes** are drawn with **low error correction**. That gives fewer, larger modules, which a camera reads more easily off a screen. Error correction is there to recover damaged codes, and the signature already catches a bad read.

App key: Ed25519 from HKDF-SHA256 (salt `prime-approve`, ikm = the KeyOS app seed via `GetAppSeed`, info `app key v1`). The app never touches the master seed.

## Structured summary line

When a request carries `verb`, `object` and `target`, the Prime draws one line inside the trusted frame, for example **Merge → PR #3 → typewright-website-audit**.

- `verb` must be one of: `Merge`, `Deploy`, `Publish`, `Delete`, `Send`, `Pay`, `Sign`, `Run`, `Grant`, `Change`.
- `object` can be up to 24 chars and `target` up to 40. Both use ASCII letters, digits, space and `# . _ / : @ -` only, with no leading or trailing spaces.
- The arrows are drawn by the app. Agents can't send them, so an agent can't fake the layout.

The summary is still supplied and signed by the agent, just like the title. The app limits how it can *look*, not whether it's *true*. What ties the request to the real action is the `hash`.

## Visual action code

Under the 8-character action code, the Review screen shows 8 colored shapes. The agent draws the same 8 on its own screen, so a person can match them at a glance.

**Rule** (`glyphs()` in `src/proto.rs`):

1. Hex-decode the request's `hash` to 32 bytes `h[0..32]`.
2. The text action code is `h[0..4]` as uppercase hex, split 4 + 4: `BF35 8E2F`.
3. Glyph `i` (for `i` = 0 to 7, left to right) comes from byte `b = h[4 + i]`:
   - color id = `b & 7` (the low 3 bits)
   - shape id = `(b >> 3) & 3` (bits 3 and 4)
   - bits 5 to 7 are unused. Bytes 12 to 31 are not shown.

The colors are the Okabe-Ito colorblind-safe palette, with white in place of its black so every glyph shows on the dark background.

| color id | name | sRGB |
|---|---|---|
| 0 | vermillion | `#D55E00` |
| 1 | orange | `#E69F00` |
| 2 | yellow | `#F0E442` |
| 3 | bluish green | `#009E73` |
| 4 | sky blue | `#56B4E9` |
| 5 | blue | `#0072B2` |
| 6 | reddish purple | `#CC79A7` |
| 7 | white | `#EDEDED` |

| shape id | shape |
|---|---|
| 0 | filled circle |
| 1 | filled square |
| 2 | ring (outlined circle) |
| 3 | outlined square |

**Test vector** (the simulator demo action; checked by `tests::demo_vector` and by an independent Python check):

```
action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":3,"method":"squash"}
         (exact bytes, no trailing newline)
SHA-256 = bf358e2fe2124f3996c349f0eaff5b137d52307d6d31d1d66d4f10785fa6b9df
code    = BF35 8E2F
bytes   = e2 12 4f 39 96 c3 49 f0
ids     = (color, shape) (2,0) (2,2) (7,1) (1,3) (6,2) (3,0) (1,1) (0,2)
glyphs  = yellow circle, yellow ring, white square, orange outlined square,
          reddish purple ring, bluish green circle, orange square, vermillion ring
```

**Colorblind note.** In simulation (Machado 2009 matrices, CIEDE2000), no two of the 8 colors fall below a ΔE00 of 10.9, whether under protanopia, deuteranopia, tritanopia or normal vision. Every color has at least 3.1:1 contrast against the app background. The shapes still do half the work, so the pattern doesn't depend on color alone. This has not yet been checked on a real Prime screen. See `docs/colorblind.md`, which is reproducible with `tools/colorblind.py`.

## What the pattern does and doesn't do

The action code and the colored shapes help a *person* notice when the request on the Prime isn't the one their agent showed, for example if it was swapped or changed on the way. They are a convenience for spotting that, not the security boundary.

The real protection is on the agent. Before acting, the agent runs `verify_reply`: it checks the reply's signature against the paired app key, and requires that the `id`, `kid` and `hash` match the exact action it's about to run and that `decision == "approve"`. An agent that skips that check isn't protected by any pattern on the screen.

## Trusted frame

The Review screen has two app-only areas:
- **the band:** the paired name, the risk level and the paired check
- **the frame:** the summary line, action code, colored shapes and countdown

Nothing the agent writes freely (title, details) is ever drawn inside either one. That text only appears in the scrolling area between them.

## Scroll gate

The slider stays locked until the request has been scrolled to the end. This is implemented, but the demo doesn't exercise it: the demo request has only two short lines of details, so it fits on one screen and the gate opens straight away. The 800-byte QR limit keeps every request short, so in practice the gate rarely triggers. It has not been tested with a request long enough to need scrolling.

## Agent-side check (required)

Before acting, the agent must run the equivalent of `verify_reply`: verify the signature with the paired app public key, then require `id` = the request it issued, `kid` = its own key id, `hash` = the action it is about to run, and `decision == "approve"`. The agent must also enforce its own expiry and treat each request id as single-use.

## Security note: replay protection lives on the agent

The Prime remembers the last 512 answered request ids so it refuses obvious replays, but that list is a convenience, not the guard. Once an id ages out, the Prime would show that request again. The real protection is the agent: single-use ids and expiry, checked on the agent side. Do not rely on the device-side list.

## Known items to test on hardware

These are untested until a dev unit arrives:

- **Real-camera QR reading at these densities.** All codes use low error correction:

  | payload | bytes | QR version | modules |
  |---|---|---|---|
  | request cap (`MAX_QR`) | 800 | 20 | 97×97 |
  | demo request | 594 | 17 | 85×85 |
  | approve reply | 416 | 13 | 69×69 |
  | deny reply with a reason | 444 | 14 | 73×73 |

  If the Prime camera struggles near 800 bytes, the cap should come down.
- **Summary fields cost about 90 bytes** of the request budget (the demo is 503 bytes without them, 594 with). Real agents with long titles and details will feel that.
- **The colored shapes on a real Prime panel.** Brightness, gamut and viewing angle can shift colors from the simulated values.

## Build and run (simulator)

Requires the Foundation SDK 1.1.0. From this folder:

    foundation develop
    foundation sim

`tools/` holds the scripts used to drive the simulator and take screenshots with `foundation-passport-drive --sim`.

The simulator has no camera, so the demo buttons generate requests on-device using a publicly known demo agent key (sim demo only, never for real use).

## Tests, docs and tools

- `src/proto.rs` has unit tests for the protocol: the glyph test vector, summary checks, QR size, and reply signing and verification. They only need `serde`, `serde_json`, `sha2`, `hex`, `base64` and `ed25519-dalek`, so you can run them on a desktop by compiling `proto.rs` in a small host crate.
- `docs/colorblind.md`: the palette check behind the colorblind note.
- `tools/colorblind.py`: re-runs that check (needs numpy). `--old` shows the previous palette.
- `tools/*.sh`: simulator driving and screenshot scripts.

## About the screenshots

The KeyOS simulator swaps the red and blue channels in its screenshots. The published screenshots have been color-corrected (R and B swapped back) so they match what the Prime actually shows. Raw simulator captures will look wrong.

## License

GPL-3.0-or-later. See `LICENSE`.
