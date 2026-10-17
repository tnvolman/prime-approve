# Prime Approve

An offline approval app for Foundation Passport Prime (KeyOS). An AI agent asks for permission with a signed QR code; the human reads the exact request on the Prime and approves or denies; the Prime answers with a signed reply QR the agent must verify before acting. No network, no trading.

Status: v0.4 (compact reply) in progress, simulator-tested only. Not yet run on hardware (see *Known items to test on hardware*).

**Read [`THREAT_MODEL.md`](THREAT_MODEL.md) first.** It says what an approval proves and what it doesn't, where the trust boundaries are, and which threats are fixed, planned or open.

## Screenshots (KeyOS simulator, color-corrected)

**Agent CLI end to end (v0.4, October 17, 2026):** a demo build's home with the **Paste** button, then a real pairing and approval driven by `pa` on a laptop: the Prime's pair-confirm screen for the `pa` agent key, its answer with the pairing code (`pa pair-accept` showed the same code), the request built by `pa request` (action code 1594 E5CC), and the reply QR that `pa verify` accepted as APPROVED. The codes were typed in through **Paste** because the simulator has no camera.

<p>
<img src="docs/screenshots/v0.4/demo-home.png" width="140" alt="Demo build home: Request, Pair and Paste buttons">
<img src="docs/screenshots/v0.4/cli-pair-confirm.png" width="140" alt="Pair this agent? for the pa CLI key">
<img src="docs/screenshots/v0.4/cli-pair-answer.png" width="140" alt="Pairing Agent 3: answer QR and pairing code">
<img src="docs/screenshots/v0.4/cli-review.png" width="140" alt="Review of the request built by pa request">
<img src="docs/screenshots/v0.4/cli-reply.png" width="140" alt="Approved reply that pa verify accepted">
</p>

**Compact reply (v0.4, October 17, 2026):** the demo request, the approved reply, the deny reasons and a denied reply ("Wrong action"). The reply QR is now 121 characters (version 5, 37×37 modules, medium error correction) and spans the full screen width, with the action code below it.

<p>
<img src="docs/screenshots/v0.4/review.png" width="140" alt="Demo request review">
<img src="docs/screenshots/v0.4/approved-reply.png" width="140" alt="Approved: full-width reply QR, version 5, action code below">
<img src="docs/screenshots/v0.4/deny-reason.png" width="140" alt="Why deny?">
<img src="docs/screenshots/v0.4/denied-reply.png" width="140" alt="Denied: full-width reply QR">
</p>

**Pairing (v0.3, October 17, 2026):** a default build with no agent, the pair-confirm screen (pairing code and agent key), naming the agent on the Prime with the on-screen keyboard, the signed answer QR for the agent with **Codes match** and **Don't match** (updated in v0.3.1; the pairing is saved only on Codes match), a relaunch showing the saved pairing, the unpair prompt, and a relaunch after unpairing (Agent 1 stays gone, Build bot stays paired). The demo agent "Cos" is a demo-build-only, in-memory agent.

<p>
<img src="docs/screenshots/v0.3/home-no-agent.png" width="140" alt="Default build: no agent paired">
<img src="docs/screenshots/v0.3/pair-confirm.png" width="140" alt="Pair this agent? with a 12-byte pairing code">
<img src="docs/screenshots/v0.3/pair-name.png" width="140" alt="Naming the agent with the on-screen keyboard">
<img src="docs/screenshots/v0.3/paired-reply.png" width="140" alt="Pairing answer: QR and pairing code, then Codes match or Don't match">
<img src="docs/screenshots/v0.3/relaunch-saved.png" width="140" alt="After relaunch: Agent 1 still paired">
<img src="docs/screenshots/v0.3/unpair.png" width="140" alt="Unpair this agent?">
<img src="docs/screenshots/v0.3/relaunch-after-unpair.png" width="140" alt="After relaunch: Agent 1 stays unpaired">
</p>

**v0.2 (October 17, 2026):** a default build (no demo agent, no demo key), a demo build with its warning banner, the demo request (high impact set by the Merge verb), and the system QR scanner opened by **Scan request** (now **Scan code**). The recent-decisions rows are left over from earlier simulator runs.

<p>
<img src="docs/screenshots/v0.2/home-default.png" width="200" alt="Default build home: no agent paired">
<img src="docs/screenshots/v0.2/demo-home.png" width="200" alt="Demo build home with the Demo key, not secure banner">
<img src="docs/screenshots/v0.2/demo-review.png" width="200" alt="Demo request review: Merge PR #2, action code 1594 E5CC">
<img src="docs/screenshots/v0.2/scanner.png" width="200" alt="System QR scanner opened from Scan request">
</p>

Earlier v0.1 screenshots:

| Home | Review | Approved reply |
|---|---|---|
| ![Home with recent decisions](docs/screenshots/home.png) | ![Review: trusted band, request, trusted frame with summary line, action code and colored shapes](docs/screenshots/review.png) | ![Approved: signed reply QR](docs/screenshots/approved-reply.png) |

| Deny reason | Replayed | Hidden text |
|---|---|---|
| ![Why deny?](docs/screenshots/deny-reason.png) | ![Already used](docs/screenshots/rejected-replayed.png) | ![Hidden characters](docs/screenshots/rejected-hidden-text.png) |

| Denied reply | Unpair | Bad signature |
|---|---|---|
| ![Denied: signed reply QR with reason](docs/screenshots/denied-reply.png) | ![Unpair this agent?](docs/screenshots/unpair.png) | ![Bad signature (tampered request)](docs/screenshots/rejected-tampered.png) |

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

**Reply QR (v0.4, compact)** `PA1:<base45(78 bytes)>`, always 121 characters. Base45 ([RFC 9285](https://www.rfc-editor.org/rfc/rfc9285)) uses only QR alphanumeric characters (`0-9 A-Z space $ % * + - . / :`), so the QR is drawn in alphanumeric mode. The packed bytes are:

| bytes | field |
|---|---|
| 1 | version, `1` |
| 1 | decision: `1` approve, `2` deny, `3` deny "wrong_action", `4` deny "not_now", `5` deny "unrecognized" |
| 8 | the first 8 bytes of the request `id` |
| 4 | time the Prime signed it, unix seconds, big-endian `u32` (`0` if the Prime's clock is unknown). Informational: the agent still enforces its own expiry |
| 64 | Ed25519 signature by the Prime's app key |

The signature covers more than is sent:

    "primeapprove-reply-v1\n" || version || decision || id (all 16 bytes) || kid (8 bytes) || hash (all 32 bytes) || time

The full request id, the agent's `kid` and the full action `hash` are never in the QR. The agent rebuilds the signed message from the request it holds, so a reply only verifies for that exact request, that agent and that exact action. There is no key id: the agent checks against the one Prime key it pinned at pairing. A deny reason is folded into the decision byte, so it is **never** possible on an approve, and an unknown reason is signed as a plain deny. If the person chooses "Don't recognize this", the Prime also offers to unpair that agent.

The old JSON reply (`primeapprove:v1r:`, 416 bytes for an approve and 444 for a deny) is gone; agents must use the compact format.

**QR codes.** The reply is drawn at **medium** error correction across the full 480-pixel screen width: 37 modules plus a 2-module quiet zone, 11 pixels per module, with a little extra white margin, so about 3 modules of quiet zone on each side. The action code stays below it. Request and pairing QRs (shown by the agent) and the pairing answer stay at low error correction.

**Reading a reply on the agent side.** `tools/decode_reply.py photo.png --pubkey <pinned Prime key> --id <request id> --kid <your kid> --hash <action hash>` decodes a photo or screenshot with zbar and verifies it the same way as `verify_reply`. It exits 0 only for a valid approve. `src/proto.rs` has a fixed test vector (`compact_reply_test_vector`) for other implementations.

App key: Ed25519 from HKDF-SHA256 (salt `prime-approve`, ikm = the KeyOS app seed via `GetAppSeed`, info `app key v1`). The app never touches the master seed.

## Agent CLI

`agent/` is the agent side: a Python 3.10+ package, `primeapprove`, with a library and a `pa` command for an AI agent or a person on a laptop. It needs `cryptography` and `qrcode`; reading QR photos also needs Pillow and `pyzbar` (or the `zbarimg` command).

    pip install './agent[photo]'
    pa init                                   # agent key in ~/.primeapprove/agent.key (mode 600, never printed)
    pa pair --png offer.png                   # scan on the Prime, name the agent, tap Pair
    pa pair-accept answer.jpg                 # shows the pairing code; type y only if the Prime shows the same
    pa request --action '{"tool":"github.merge_pull_request","repo":"you/repo","pr":7,"head":"<sha>"}' \
        --title "Merge PR #7 into main" --verb Merge --object "PR #7" --target repo
    pa verify reply.jpg && echo "run the action"    # exit 0 only for a valid, unused approve

- **`pa pair-accept`** checks the Prime's signed answer, then pins the Prime's key in `~/.primeapprove/prime.json` **only** if you answer `y` to "Does the Prime show the same code?". Anything else pins nothing; tap **Don't match** on the Prime too.
- **`pa request`** hashes the **exact bytes** of `--action` (or `--action-file`); run exactly those bytes. It applies the Prime's own checks (printable ASCII, lengths, allowed verbs and summary characters, expiry of 10 minutes or less, the 800-byte cap), marks high-impact verbs as elevated, and refuses `--risk routine` for them. It prints the QR (terminal, and `--png`) and the action code with its colored shapes, and saves the request in `~/.primeapprove/pending/`.
- **`pa verify`** reads the reply (text, `-` for stdin, or a photo), finds the pending request by its id prefix, verifies it against the **pinned** key over the full id, kid and action hash, and prints `APPROVED`, `DENIED(reason)` or `INVALID (why)`. Exit code 0 only for an approve. An answered request is marked used, so the same reply (or any second reply) is refused. Expired requests are refused.
- The library mirrors `src/proto.rs` byte for byte. Its tests (`cd agent && pytest`) reproduce the Rust test vectors (demo hash `1594e5cc…`, action code, glyphs, kid, pairing code, the compact reply vector) and drive the CLI. **Cross tests:** `agent/tests/make_fixtures.py` writes `host-tests/fixtures/py_to_rust.json` (a Python-built request and pairing offer), which the Rust host tests accept, including checking that Python's request JSON is byte-identical to serde's. The Rust host tests write `host-tests/fixtures/rust_to_py.json` (Rust-signed replies and a pairing answer), which the Python tests verify. Both sides fail if a fixture drifts.
- **Simulator:** demo builds have a **Paste** button, a text field that goes through the same handler as a scan. `foundation-passport-drive --sim input-text` can type a code into it, 48 characters per call, because the simulator has no camera. Non-demo builds don't have it.

## Pairing

Pairing is two-way: the Prime learns the agent's key, and the agent learns (and pins) the Prime's key.

1. **The agent shows a pairing offer QR:** `primeapprove:pair:v1:<b64url(json)>.<b64url(sig)>`. JSON is `{pk, exp}`: the agent's Ed25519 public key (64 hex chars) and an expiry no more than 10 minutes out. The signature is by that same key over `"primeapprove-pair-v1\n" + json`, which proves the agent holds the key. The offer has **no name**: the agent never names itself.
2. **The Prime shows "Pair this agent?"** with the pairing code and the key fingerprint, inside a trusted frame. The person types a name for the agent on the Prime (printable ASCII, 1 to 24 characters; left blank, it becomes "Agent N"). That name is what the review band shows from then on.
3. **On Pair, the Prime shows its answer QR, but saves nothing yet:** `primeapprove:paired:v1:<b64url(json)>.<b64url(sig)>`. JSON is `{kid, app_pk}`: the paired agent's key id and the Prime's app public key. It is signed by the app key over `"primeapprove-paired-v1\n" + json`. The pairing is held in memory only, as *pending*.
4. **The agent checks the answer** (`verify_paired_reply`), which gives it the Prime's app key, and shows the pairing code it computes from the two keys. The agent's own user compares that code with the Prime's.
5. **Both sides commit only when the codes match.** On the Prime, the person taps **Codes match**, which saves the pairing, or **Don't match**, which throws it away and saves nothing. Leaving the answer screen any other way, or relaunching the app, also throws it away. On the agent, the agent **pins the Prime's key only after its own user confirms that the codes match**. From then on the agent must verify every reply against that pinned key and reject a reply signed by any other key, even a validly signed one (threat model rule 1).

Why the order matters: the agent only learns the Prime's key from the answer QR, so before that screen it has no code to compare. Saving on the earlier Pair tap would commit a pairing the person never got to check. The pending-then-confirm rule is a pure helper, `resolve_pairing`, with host tests: nothing is saved without a confirm, nothing is saved on Don't match, and the pairing is saved on Codes match.

**Pairing code.** Both screens show the first 12 bytes of `SHA-256("prime-approve pair v1" || agent_pk || app_pk)` as six groups of four uppercase hex characters, for example `3F57 5D3C E654 3053 C615 D2E5`. The agent computes it from its own key and the pinned app key. If anyone swapped either key on the way, the codes differ. The person should pair only when the codes match. The signatures prove each side holds its key; the code comparison is what proves it is the *right* key.

**Saved, and removable.** Confirmed pairings are saved in the app's storage and survive a restart. Up to 5 agents can be paired; re-pairing a key that's already paired just renames it. Tap an agent on the home screen to unpair it (or choose "Don't recognize this" when denying one of its requests). Unpairing is saved, so the agent stays unpaired after a restart, and the agent's requests are refused as "Bad signature" from then on.

**Scanning.** **Scan code** takes either a request or a pairing offer, and the Launcher hands both to the app (`primeapprove:v1:` and `primeapprove:pair:v1:` match rules). Demo builds add a **Pair** button (next to **Request** and **Paste**) that generates a pairing offer from a fresh random key and feeds it through the same handler, because the simulator has no camera. A fresh random key means a demo pairing never leaves a publicly known key paired.

Sizes: the pairing offer is 228 bytes and the answer 246 bytes, both well under the 800-byte cap.

## Structured summary line

When a request carries `verb`, `object` and `target`, the Prime draws one line inside the trusted frame, for example **Merge → PR #2 → typewright-website-audit**.

- `verb` must be one of: `Merge`, `Deploy`, `Publish`, `Delete`, `Send`, `Pay`, `Sign`, `Run`, `Grant`, `Change`.
- `object` can be up to 24 chars and `target` up to 40. Both use ASCII letters, digits, space and `# . _ / : @ -` only, with no leading or trailing spaces.
- The arrows are drawn by the app. Agents can't send them, so an agent can't fake the layout.

The summary is still supplied and signed by the agent, just like the title. The app limits how it can *look*, not whether it's *true*. What ties the request to the real action is the `hash`.

## Visual action code

Under the 8-character action code, the Review screen shows 8 colored shapes. The agent draws the same 8 on its own screen, so a person can match them at a glance.

**Rule** (`glyphs()` in `src/proto.rs`):

1. Hex-decode the request's `hash` to 32 bytes `h[0..32]`.
2. The text action code is `h[0..4]` as uppercase hex, split 4 + 4: `1594 E5CC`.
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
action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}
         (exact bytes, no trailing newline)
SHA-256 = 1594e5cc61b278e99dba75aad80d8b2dd41e135820630c1e12584dda3b95d9d8
code    = 1594 E5CC
bytes   = 61 b2 78 e9 9d ba 75 aa
ids     = (color, shape) (1,0) (2,2) (0,3) (1,1) (5,3) (2,3) (5,2) (2,1)
glyphs  = orange circle, yellow ring, vermillion outlined square, orange square,
          blue outlined square, yellow outlined square, blue ring, yellow square
```

**Colorblind note.** In simulation (Machado 2009 matrices, CIEDE2000), no two of the 8 colors fall below a ΔE00 of 10.9, whether under protanopia, deuteranopia, tritanopia or normal vision. Every color has at least 3.1:1 contrast against the app background. The shapes still do half the work, so the pattern doesn't depend on color alone. This has not yet been checked on a real Prime screen. See `docs/colorblind.md`, which is reproducible with `tools/colorblind.py`.

## What the pattern does and doesn't do

The action code and the colored shapes help a *person* notice when the request on the Prime isn't the one their agent showed, for example if it was swapped or changed on the way. They are a convenience for spotting that, not the security boundary.

The real protection is on the agent. Before acting, the agent runs `verify_reply`: it rebuilds the signed message from its own request `id`, its own `kid` and the hash of the exact action it's about to run, checks the reply's signature over that against the pinned app key, and requires the decision to be approve. An agent that skips that check isn't protected by any pattern on the screen.

## Trusted frame

The Review screen has two app-only areas:
- **the band:** the paired name, the risk level and the paired check
- **the frame:** the summary line, action code, colored shapes and countdown

Nothing the agent writes freely (title, details) is ever drawn inside either one. That text only appears in the scrolling area between them.

What the frame means: the request is **verified from the paired agent, unchanged**, meaning it was signed by that agent's key and not altered on the way. It does not mean the action is safe or that the Prime has confirmed the summary is true. The summary is supplied by the agent.

## Scroll gate

The slider stays locked until the request has been scrolled to the end. This is implemented, but the demo doesn't exercise it: the demo request has only two short lines of details, so it fits on one screen and the gate opens straight away. The 800-byte QR limit keeps every request short, so in practice the gate rarely triggers. It has not been tested with a request long enough to need scrolling.

## Agent-side check (required)

Before acting, the agent must run the equivalent of `verify_reply` (or `decode_reply`, which also returns a deny and its reason): check that the reply's 8-byte id prefix matches the request it issued, rebuild the signed message from the full `id`, its own `kid` and the hash of the action it is about to run, verify the signature with the pinned app public key, and require decision `1` (approve). The agent must also enforce its own expiry and treat each request id as single-use.

## Security note: replay protection lives on the agent

The Prime remembers the last 512 answered request ids so it refuses obvious replays, but that list is a convenience, not the guard. Once an id ages out, the Prime would show that request again. The real protection is the agent: single-use ids and expiry, checked on the agent side. Do not rely on the device-side list.

## Known items to test on hardware

These are untested until a dev unit arrives:

- **Real-camera QR reading at these densities.** Request and pairing codes use low error correction, the reply medium:

  | payload | bytes | QR version | modules |
  |---|---|---|---|
  | request cap (`MAX_QR`) | 800 | 20 | 97×97 |
  | demo request | 581 | 17 | 85×85 |
  | approve or deny reply (v0.4, medium error correction) | 121 | 5 | 37×37 |
  | old JSON approve reply (before v0.4) | 416 | 13 | 69×69 |
  | old JSON deny reply with a reason (before v0.4) | 444 | 14 | 73×73 |

  If the Prime camera struggles near 800 bytes, the cap should come down.
- **A laptop webcam reading the reply off a real Prime.** In simulation, zbar decodes the reply screenshot at full size and downscaled to 50%, 30%, 20% and 15%, with and without blur; the old 416-byte reply decoded at full size and 50% but failed at 50% with blur and at every smaller size. A real webcam test still needs a person: show an approved reply to the webcam, take a photo, and run `tools/decode_reply.py` on it.
- **Summary fields cost about 90 bytes** of the request budget (the demo is 490 bytes without them, 581 with). Real agents with long titles and details will feel that.
- **The colored shapes on a real Prime panel.** Brightness, gamut and viewing angle can shift colors from the simulated values.

## Scanning

**Scan code** opens the system QR scanner (this needs the `ShowModal` permission). A request scanned from the Launcher's own scanner is handed to the app through the `primeapprove:v1:` QR match rule and picked up at launch. Either way, the text goes through the same checks: size, signature, paired agent, plain-ASCII text, expiry no more than 10 minutes out, and single use. The simulator has no camera, so neither path can be exercised there.

## Build and run (simulator)

Requires the Foundation SDK 1.1.0. From this folder:

    foundation develop
    foundation sim

A default build has no paired agent and no demo key. Pair an agent by scanning its pairing code (see *Pairing*).

**Demo build.** Building with the `demo` cargo feature pairs a demo agent whose private key is public (anyone can sign as it), adds **Request** (a demo request), **Pair** (a demo pairing offer) and **Paste** (type a code in, for the simulator) buttons and, in debug builds, the Tampered, Replay and Hidden text tests. Every screen then shows a red **Demo key · not secure** banner. Never put a demo build on a device you use for real. The demo request is a real, already-merged PR (`tnvolman/typewright-website-audit` #2), pinned to its head commit.

`tools/` holds the scripts used to drive the simulator and take screenshots with `foundation-passport-drive --sim`.

## Forking

Change `app-id` in `app-config.toml`. The app's signing key is derived from the app seed KeyOS gives that app id, so a fork that keeps the id would share key material with this app. Also fill in the `[publisher]` fields with your own details.

## Tests, docs and tools

- `src/proto.rs` has unit tests for the protocol: the glyph test vector, summary checks, QR size, the compact reply (round trip, every single-bit tamper fails, wrong pinned key, wrong request hash, id or kid, 78-byte payload and QR version 5, base45 against RFC 9285, a fixed test vector), and one test per finding from the October 2026 review (plain-ASCII text, the expiry limit, high impact set by the verb). Pending-pairing tests check that nothing is saved without Codes match. Pairing tests cover the offer and answer roundtrip, a forged offer signature, a far-future expiry, name checks, the pairing code (same both ways, changes if either key changes) and agent-side pinning (a reply from any other app key fails). One test, `known_gap_summary_not_bound_to_hash`, deliberately pins the open gap that the summary isn't tied to the hash yet; it gets flipped when the Prime reads the action itself. Run them on any computer with `cd host-tests && cargo test` (no KeyOS SDK needed). The host tests also include the cross tests with the Python agent library (`host-tests/src/lib.rs`).
- `docs/colorblind.md`: the palette check behind the colorblind note.
- `tools/colorblind.py`: re-runs that check (needs numpy). `--old` shows the previous palette.
- `agent/`: the agent-side library and `pa` CLI (see *Agent CLI*).
- `tools/decode_reply.py`: a wrapper around the agent library: `pa verify PHOTO`, or a check against explicit `--pubkey --id --kid --hash` values.
- `tools/*.sh`: simulator driving and screenshot scripts.

## About the screenshots

The KeyOS simulator swaps the red and blue channels in its screenshots. The published screenshots have been color-corrected (R and B swapped back) so they match what the Prime actually shows. Raw simulator captures will look wrong.

## License

GPL-3.0-or-later. See `LICENSE`.
