# Prime Approve

An offline approval app for Foundation Passport Prime (KeyOS). An AI agent asks for permission with a signed QR code; the human reads the exact request on the Prime and approves or denies; the Prime answers with a signed reply QR the agent must verify before acting. No network, no trading.

Status: **v0.7, simulator only.** Not yet run on hardware (see *Known items to test on hardware*). The version tags on the screenshot captions below record when each set was taken.

**Read [`THREAT_MODEL.md`](THREAT_MODEL.md) first.** It says what an approval proves and what it doesn't, where the trust boundaries are, and which threats are fixed, planned or open.

## Screenshots (KeyOS simulator, color-corrected)

**Fresh pairing code (v0.7, October 17, 2026):** since item 17 the Prime picks a random 16-byte nonce for each pairing, sends it in its answer (`primeapprove:paired:v2:`) and mixes it into the pairing code. A pairing offer from `pa pair --text` typed in through **Paste**: the Prime's pair-confirm screen and its answer both show `99A7 F2AF CFF5 B6AD A7E6 8185`; the answer QR, decoded from the screenshot and given to `pa pair-accept`, produced the same code ([text](docs/screenshots/v0.7/pair-nonce-check.txt)).

<p>
<img src="docs/screenshots/v0.7/pair-nonce-confirm.png" width="140" alt="Pair this agent? with pairing code 99A7 F2AF CFF5 B6AD A7E6 8185">
<img src="docs/screenshots/v0.7/pair-nonce-answer.png" width="140" alt="Pairing answer QR (v2, with nonce) and the same pairing code">
</p>

**Base branch on the Prime (v0.7, October 17, 2026):** since item 16 the merge action names the branch it merges into, and the Prime says so in the trusted frame. Left to right: the demo request (action now includes `"base":"main"`, code **F961 B2D1**) reads **Merge PR #2 into main**; its approved reply; a request for the same PR aimed at `release` (built with the Python library, typed in through **Paste**) reads **Merge PR #2 into release** just as plainly, with a different code (5D86 5564); and Recent decisions on the home screen record the base.

<p>
<img src="docs/screenshots/v0.7/review-into-main.png" width="140" alt="Review: Merge PR #2 into main → tnvolman/typewright-website-audit, code F961 B2D1">
<img src="docs/screenshots/v0.7/approved-reply-main.png" width="140" alt="Approved reply QR, code F961 B2D1">
<img src="docs/screenshots/v0.7/review-into-release.png" width="140" alt="Review: Merge PR #2 into release → tnvolman/typewright-website-audit, code 5D86 5564">
<img src="docs/screenshots/v0.7/home-recent-base.png" width="140" alt="Home: recent decisions record into release and into main">
</p>

**GitHub gate, live (v0.6, October 17, 2026):** a request built by `pa request` for the real head of [PR #1](https://github.com/tnvolman/prime-approve/pull/1) (a demo PR, left open), approved on the simulator; `pa gate` then posted the green `prime-approve` status on exactly that SHA. After one more push, the new head had no status, and the old replies were refused by the gate and, in merge mode, by GitHub itself (409). The proof card is rendered from the GitHub API output ([text](docs/screenshots/v0.6/gate-proof.txt)).

<p>
<img src="docs/screenshots/v0.6/gate-review.png" width="140" alt="Review: Merge → PR #1 → tnvolman/prime-approve, squash · head e4183b5, code 3394 D7A6">
<img src="docs/screenshots/v0.6/gate-approved-reply.png" width="140" alt="Approved reply QR that pa gate verified">
<img src="docs/screenshots/v0.6/gate-proof.png" width="420" alt="GitHub API proof: success status on the approved SHA, none on the new head, old replies refused">
</p>

**What the Prime shows (v0.5, October 17, 2026):** three requests built by `pa request` and typed in through **Paste**. A known merge: the Prime parsed the action and drew **Merge → PR #2 → tnvolman/typewright-website-audit** and `squash · head 33393c6` itself; the reply was accepted by `pa verify`. A lying request: the agent's title and details say PR #2 into the real repo, but the action merges PR #9 into `evil/other-repo`, and the parsed band shows exactly that (denied as "Wrong action"). An unknown tool (`github.delete_repo`) titled "Run the unit tests": shown raw under a yellow "Unrecognized action · read carefully" label and marked high impact.

<p>
<img src="docs/screenshots/v0.5/known-merge.png" width="140" alt="Known merge: parsed summary in the trusted frame, agent title under Agent says">
<img src="docs/screenshots/v0.5/known-merge-approved.png" width="140" alt="Approved reply for the known merge">
<img src="docs/screenshots/v0.5/lying-title.png" width="140" alt="Lying title: the agent says PR #2, the parsed band says PR #9 to evil/other-repo">
<img src="docs/screenshots/v0.5/unknown-raw.png" width="140" alt="Unknown tool: raw action JSON under a yellow Unrecognized action label, high impact">
</p>

**Agent CLI end to end (v0.4, October 17, 2026):** a demo build's home with the **Paste** button, then a real pairing and approval driven by `pa` on a laptop: the Prime's pair-confirm screen for the `pa` agent key, its answer with the pairing code (`pa pair-accept` showed the same code), the request built by `pa request` (action code 1594 E5CC, the demo code before v0.7 added the base branch), and the reply QR that `pa verify` accepted as APPROVED. The codes were typed in through **Paste** because the simulator has no camera.

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
<img src="docs/screenshots/v0.2/demo-review.png" width="200" alt="Demo request review: Merge PR #2, action code 1594 E5CC (before the base branch was added)">
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

**Request QR (v0.5)** `primeapprove:v2:<b64url(json)>.<b64url(ed25519 sig)>`. The signature covers `"primeapprove-req-v2\n" + json`, the exact bytes received. The whole QR must be 800 bytes or less. v1 requests (which carried an agent-computed `hash` and an agent-written summary) are refused.

JSON fields:

| field | meaning |
|---|---|
| `id` | 32 hex chars (128-bit), single-use |
| `kid` | first 16 hex chars of SHA-256(agent public key) |
| `agent` | the agent's display name. Checked for hidden characters but **not shown in the trusted band**; the band shows the name you gave the agent when you paired it |
| `title` | 60 chars or fewer |
| `details` | 280 chars or fewer; newlines allowed |
| `action` | the exact action bytes the agent will run, as a JSON string: a JSON object with a string `"tool"`, printable ASCII (newlines allowed), 400 bytes or less. The Prime parses it and computes the action hash, SHA-256 of these bytes, itself |
| `exp` | expiry, unix seconds |

Only these seven fields are allowed (in this order when built by `pa`); unknown fields, duplicates, `risk`, `hash`, `verb`, `object` and `target` are rejected. The known merge request is 597 to 609 bytes.

The Prime rejects a request that is:
- too large or malformed
- badly signed (checked against paired keys before anything is parsed)
- carrying a `kid` that doesn't match the signing key
- hiding control, bidi or zero-width characters in display text or the action
- carrying an action that isn't a JSON object with a string `tool`, is over 400 bytes, fails the ASCII allowlist, or names a known tool with missing, extra, duplicate or invalid fields
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
    pa request --action '{"tool":"github.merge_pull_request","repo":"you/repo","pr":7,"base":"main","method":"squash","head":"<40-hex sha>"}' \
        --title "Merge PR #7 into main"
    pa verify reply.jpg && echo "run the action"    # exit 0 only for a valid, unused approve

- **`pa pair-accept`** checks the Prime's signed answer, then pins the Prime's key in `~/.primeapprove/prime.json` **only** if you answer `y` to "Does the Prime show the same code?". Anything else pins nothing; tap **Don't match** on the Prime too.
- **`pa request`** puts the **exact bytes** of `--action` (or `--action-file`) into the request; run exactly those bytes. `--title` and `--details` are optional and only ever shown as "Agent says". It applies the Prime's own checks (the action parser and allowlist, text lengths, expiry of 10 minutes or less, the 800-byte cap) and prints what the Prime will show: the parsed summary for a known tool, or a warning that an unknown tool will be shown raw and marked high impact. Then it prints the QR (terminal, and `--png`) and the action code with its colored shapes, and saves the request in `~/.primeapprove/pending/`.
- **`pa verify`** reads the reply (text, `-` for stdin, or a photo), finds the pending request by its id prefix, verifies it against the **pinned** key over the full id, kid and action hash, and prints `APPROVED`, `DENIED(reason)` or `INVALID (why)`. Exit code 0 only for an approve. An answered request is marked used, so the same reply (or any second reply) is refused. Expired requests are refused.
- **`pa verify` is not a lock on its own.** If it runs in the same account as the agent, a compromised agent can skip it, answer the pairing prompt itself, or edit its saved requests and pinned key. It becomes a real control only when it runs where the agent can't reach, with the credential behind it: that is the **GitHub gate** below (see rule 4 in [`THREAT_MODEL.md`](THREAT_MODEL.md): don't let the agent hold the credential it is asking approval to use).
- **Replacing the pinned Prime is deliberate.** If a different Prime key is already pinned, `pa pair-accept` shows the old and new key fingerprints with the warning "This replaces the Prime you trust" and pins only if you type `replace`. Re-pairing the same Prime is a plain `y`.
- The library mirrors `src/proto.rs` byte for byte, including the action parser: `host-tests/fixtures/actions.json` holds 62 shared parsing cases (known, unknown and rejected actions, including the `\u` look-alikes and the base-branch rules) that both the Rust and the Python tests run. Its tests (`cd agent && pytest`) reproduce the Rust test vectors (demo hash `f961b2d1…`, action code, glyphs, kid, pairing code, the compact reply vector) and drive the CLI. **Cross tests:** `agent/tests/make_fixtures.py` writes `host-tests/fixtures/py_to_rust.json` (Python-built known, lying-title and unknown-tool requests and a pairing offer), which the Rust host tests accept, including checking that Python's request JSON is byte-identical to serde's. The Rust host tests write `host-tests/fixtures/rust_to_py.json` (Rust-signed replies and a pairing answer), which the Python tests verify. Both sides fail if a fixture drifts.
- **Simulator:** demo builds have a **Paste** button, a text field that goes through the same handler as a scan. `foundation-passport-drive --sim input-text` can type a code into it, 48 characters per call, because the simulator has no camera. Non-demo builds don't have it.

## Pairing

Pairing is two-way: the Prime learns the agent's key, and the agent learns (and pins) the Prime's key.

1. **The agent shows a pairing offer QR:** `primeapprove:pair:v1:<b64url(json)>.<b64url(sig)>`. JSON is `{pk, exp}`: the agent's Ed25519 public key (64 hex chars) and an expiry no more than 10 minutes out. The signature is by that same key over `"primeapprove-pair-v1\n" + json`, which proves the agent holds the key. The offer has **no name**: the agent never names itself.
2. **The Prime shows "Pair this agent?"** with the pairing code and the key fingerprint, inside a trusted frame. The person types a name for the agent on the Prime (printable ASCII, 1 to 24 characters; left blank, it becomes "Agent N"). That name is what the review band shows from then on.
3. **On Pair, the Prime shows its answer QR, but saves nothing yet:** `primeapprove:paired:v2:<b64url(json)>.<b64url(sig)>`. JSON is exactly `{kid, app_pk, nonce}`: the paired agent's key id, the Prime's app public key, and `nonce`, 16 fresh random bytes (32 lowercase hex) the Prime picked for this pairing when it showed "Pair this agent?". It is signed by the app key over `"primeapprove-paired-v2\n" + json`. A v1 answer (no nonce) is refused. The pairing is held in memory only, as *pending*.
4. **The agent checks the answer** (`verify_paired_reply`), which gives it the Prime's app key and nonce, and shows the pairing code it computes from the two keys and the nonce. The agent's own user compares that code with the Prime's.
5. **Both sides commit only when the codes match.** On the Prime, the person taps **Codes match**, which saves the pairing, or **Don't match**, which throws it away and saves nothing. Leaving the answer screen any other way, or relaunching the app, also throws it away. On the agent, the agent **pins the Prime's key only after its own user confirms that the codes match**. From then on the agent must verify every reply against that pinned key and reject a reply signed by any other key, even a validly signed one (threat model rule 1).

Why the order matters: the agent only learns the Prime's key from the answer QR, so before that screen it has no code to compare. Saving on the earlier Pair tap would commit a pairing the person never got to check. The pending-then-confirm rule is a pure helper, `resolve_pairing`, with host tests: nothing is saved without a confirm, nothing is saved on Don't match, and the pairing is saved on Codes match.

**Pairing code (v2, item 17).** Both screens show the first 12 bytes of `SHA-256("prime-approve pair v2" || agent_pk || app_pk || nonce)` as six groups of four uppercase hex characters. Test vector: agent seed `[1; 32]`, app seed `[7; 32]`, nonce `[0x42; 16]` gives `7DBE C4AE 5C43 71E5 BC30 2FC6` (`pairing_code_mixes_the_primes_nonce` in `src/proto.rs`, reproduced in `agent/tests/test_vectors.py`). The agent computes it from its own key, the app key and the nonce in the answer. If anyone swapped either key (or the nonce) on the way, the codes differ. Because the Prime picks a fresh nonce every time, the same two keys show a new code at every pairing, so a code seen or recorded once is no use at the next pairing. The nonce doesn't replace the comparison: it only makes each code single-use. The person should pair only when the codes match. The signatures prove each side holds its key; the code comparison is what proves it is the *right* key.

**Saved, and removable.** Confirmed pairings are saved in the app's storage and survive a restart. Up to 5 agents can be paired; re-pairing a key that's already paired just renames it. Tap an agent on the home screen to unpair it (or choose "Don't recognize this" when denying one of its requests). Unpairing is saved, so the agent stays unpaired after a restart, and the agent's requests are refused as "Bad signature" from then on.

**Scanning.** **Scan code** takes either a request or a pairing offer, and the Launcher hands both to the app (`primeapprove:v2:` and `primeapprove:pair:v1:` match rules). Demo builds add a **Pair** button (next to **Request** and **Paste**) that generates a pairing offer from a fresh random key and feeds it through the same handler, because the simulator has no camera. A fresh random key means a demo pairing never leaves a publicly known key paired.

Sizes: the pairing offer is 228 bytes and the answer 304 bytes (246 before the nonce), both well under the 800-byte cap.

## What the Prime shows

Since v0.5 the Prime doesn't take the agent's word for what the action is. The request carries the action bytes themselves; the Prime parses them, computes the action hash from the bytes it received, and builds the summary from the parsed action.

**Known tools** have a fixed parser in `src/proto.rs` (`action_view`). There is one so far:

| tool | fields (exactly these) | the Prime draws |
|---|---|---|
| `github.merge_pull_request` | `repo` (`owner/name`, letters, digits, `- _ .`, 64 chars or less), `pr` (integer above 0), `base` (the branch it merges into: 1 to 100 of `A-Z a-z 0-9 . _ / -`, not starting with `-` or `/`, no `..` or `//`, not ending in `/` or `.lock`), `method` (`merge`, `squash` or `rebase`), `head` (40 lowercase hex) | **Merge PR #&lt;pr&gt; into &lt;base&gt; → &lt;repo&gt;** and `<method> · head <first 7 of head>` |

For a known tool, the summary line, the detail line and the amber "High impact" band come **only** from the parsed action. The agent's title and details appear smaller, under **Agent says**, in the scrolling area. A title that says "PR #2" can't change a band that says **PR #9 → evil/other-repo** (see the screenshots above). Since v0.7 (item 16) the base branch is part of the action, so the line reads **Merge PR #2 into main → …**, and a PR aimed at another branch says so just as plainly (**into release**). A known tool with a missing, extra, duplicate or badly formed field is refused, never shown with a friendlier view.

**Unknown tools** (any other `"tool"`) are allowed, but the Prime shows the raw action JSON exactly as signed, character-wrapped and scrollable, under a yellow **Unrecognized action · read carefully** label. The frame says "Unrecognized: &lt;tool&gt;" and the request is always marked high impact. You have to read it.

**Refused outright:** an action that isn't valid JSON (as `serde_json` reads it: no `NaN`, no lone surrogates), isn't an object with a string `tool`, is over 400 bytes, has anything outside printable ASCII and newline, uses a `\u` escape anywhere, or has a tool name outside `A-Z a-z 0-9 . _ -` (1 to 64 characters). The last two close a look-alike trick: `"github.merge_pull_reque\u0455t"` is plain ASCII on the wire but decodes to a Cyrillic `ѕ`. With no `\u` escapes and that character set, the tool name on screen is always exactly the raw text.

The hash is plain SHA-256 of the action bytes. Adding `"base":"main"` to the demo action in v0.7 changed its hash to `f961b2d1…` and its action code to **F961 B2D1** (it was `1594e5cc…` / **1594 E5CC**), and with it the compact reply test vector. The arrow is drawn by the app. Recent decisions on the home screen record what the Prime showed (the parsed summary or "Unrecognized: tool"), not the agent's title.

## GitHub gate

`pa verify` tells an agent whether it was approved; it can't stop a compromised agent from going ahead anyway. The gate makes the approval **enforceable**: it holds the GitHub token, verifies the Prime's reply, and only then marks the **exact PR head commit** with the commit status `prime-approve/<base>` (for example `prime-approve/main`, state `success`), or merges that exact commit. With branch protection on main requiring `prime-approve/main`, GitHub won't merge into main without an approval that named main.

> **Until branch protection requires the `prime-approve/main` check, a green check is only advice:** anyone with write access can still merge. This repo's main is **not Prime-protected** today: the check stays advisory until the five conditions in [docs/DECISIONS.md](docs/DECISIONS.md) are all true.

    pa gate-trust --prime-key <Prime app key hex> --agent-key <agent public key hex>   # once
    #   add --simulator when the "Prime" key is a KeyOS simulator's: statuses then say "Approved in simulator"
    # the gate reads its own token from <gate home>/token (or --token-file); never printed.
    # $GITHUB_TOKEN is ignored unless you pass --token-from-env, so it never picks up the agent's token.
    pa gate request.txt reply.jpg                  # --mode status (default)
    pa gate request.txt reply.jpg --mode merge     # merge the approved SHA instead

What it checks, in order (any failure refuses and posts nothing):
1. **The request** (the signed `primeapprove:v2:` text that `pa request --text` prints, a file holding it, or a photo) is signed by an agent key the gate pinned, with exactly the seven fields (no repeats, no extras) and the action through the **same strict parser** as the Prime. The gate hashes those exact action bytes; it never rebuilds the action from its fields.
2. **Known tools only.** Anything the Prime shows as "Unrecognized" is refused, even when approved.
3. **The reply** verifies against the gate's own pinned Prime key over the request id, the agent's kid and that hash, and the request hasn't expired.
4. **The PR** (GitHub REST API) has the action's repo and number, is open, its current head SHA equals the action's `head`, and its base branch (`base.ref`) equals the action's `base`. A PR retargeted after approval is refused with "base moved".
5. **Single use**, recorded in the gate's own store; then it acts:
   - `--mode status`: `POST /repos/{repo}/statuses/{head}` with `context=prime-approve/<base>` (e.g. `prime-approve/main`), `state=success` and `description="Approved on Prime · code F961 B2D1"` ("Approved in simulator · …" when the gate's pinned Prime key was marked with `pa gate-trust --simulator`, so a simulator approval never reads as a real Prime's on GitHub). A deny posts `state=failure`. One context per base, so an approval for `release` can never satisfy a check required on `main`.
   - `--mode merge`: fetches the PR once more and re-checks its base right before `PUT /repos/{repo}/pulls/{n}/merge` with `sha=<approved head>` and `merge_method=<method>`. GitHub itself refuses with 409 if the head moved. GitHub's merge call can't check the base, so a retarget in the moment between that last check and the merge isn't caught (status mode with the required check doesn't have this gap: the context names the base). A deny merges nothing.

Exit codes: 0 done, 1 denied, 2 refused. HTTP is standard-library `urllib`; `--api` (or `PRIMEAPPROVE_GITHUB_API`) points it at another base URL, which the tests use for a local fake GitHub.

**Run it where the agent can't reach.** The gate keeps its **own** state dir (`~/.primeapprove-gate/`, or `$PRIMEAPPROVE_GATE_HOME`, or `--gate-home`), separate from the agent's `~/.primeapprove/`: its own pinned Prime key, its own pinned agent keys, its own used-request records, its own token. Put it on a different machine or a different OS account from the agent, or in a CI job whose definition and secrets the agent can't modify (for example a workflow on a protected branch, triggered by a person, with the token as a repository secret). If the agent can read the gate's token or edit its state, the gate protects nothing.

**Require the check (repository settings, done by a person):** Settings → Branches (or Rules → Rulesets) → protect `main` → *Require status checks to pass before merging* → add `prime-approve/main` (the context names the branch; the old plain `prime-approve` context is no longer posted). Keep *Do not allow bypassing the above settings* (or *Include administrators*) on, and give the agent's own token no admin rights. The `prime-approve/main` context only appears in the picker after the gate has posted it once.

**Why a retargeted PR stays out (v0.7).** The base branch is in the signed action and shown on the Prime ("into main"). The gate refuses a PR whose base no longer matches, and the status it posts is named for the approved base: a PR approved into `release` and then retargeted to `main` has only `prime-approve/release`, which doesn't satisfy a check required on main. `agent/tests/test_review_base_branch.py` guards this.

**Why a moved head stays out.** A commit status belongs to one SHA. Pushing anything to the PR makes a new head SHA with no `prime-approve/<base>` status, so the required check is missing again until a new request for the new head is approved. The gate also refuses an old reply for a moved head, and merge mode passes the approved SHA to GitHub, which refuses a different head. This was shown live on [PR #1](https://github.com/tnvolman/prime-approve/pull/1) (see the screenshots).

**Residual risks.**
- **Admins can bypass** branch protection unless bypassing is disabled, and anyone who can change the settings can remove the requirement.
- **Until the required check comes only from the gate's identity, any token with commit-status write access, including the agent's, can post a fake `prime-approve/<base>` success.** Give the agent a fine-grained token without *Commit statuses* or merge rights, or have the gate post as its own GitHub App.
- **Pin the check to the gate's App.** GitHub can tie a required status check, including a plain commit status, to one GitHub App, and then a same-named status from anyone else doesn't satisfy it ([GitHub changelog](https://github.blog/changelog/2021-12-01-ensure-required-status-checks-provided-by-the-intended-app/)). That needs the gate to post as its own App, and one status posted by the App before the rule is added. Today the gate posts with a personal token, so this isn't done yet.
- **An agent that can drive the Prime can approve for itself.** Foundation's `foundation-passport-drive` can tap "approve" in the simulator (`tools/flow.sh` does exactly that) and on a dev unit plugged into the agent's machine with Developer Mode on. Real approvals must come from a Prime the agent can't drive.
- **The token's scope is the gate's blast radius.** A classic `repo` token can do much more than post statuses; prefer a fine-grained token limited to this repository with *Commit statuses: write* (plus *Pull requests: read*, and *Contents: write* only for merge mode).
- The approval names the base **branch**, not the base branch's commit: merging into a branch that gained commits since approval is GitHub's normal behavior.
- **Merge mode's last-moment retarget.** Merge mode re-checks the base right before the merge call, but GitHub's merge API can't check the base itself, so a retarget in that short window isn't caught. Status mode with the required `prime-approve/main` check has no such window.

## Visual action code

Under the 8-character action code, the Review screen shows 8 colored shapes. The agent draws the same 8 on its own screen, so a person can match them at a glance.

**Rule** (`glyphs()` in `src/proto.rs`):

1. Hex-decode the request's `hash` to 32 bytes `h[0..32]`.
2. The text action code is `h[0..4]` as uppercase hex, split 4 + 4: `F961 B2D1`.
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
action = {"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"base":"main","method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}
         (exact bytes, no trailing newline)
SHA-256 = f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d
code    = F961 B2D1
bytes   = 33 3f b6 d7 ca bf ca 5d
ids     = (color, shape) (3,2) (7,3) (6,2) (7,2) (2,1) (7,3) (2,1) (5,3)
glyphs  = bluish green ring, white outlined square, reddish purple ring, white ring,
          yellow square, white outlined square, yellow square, blue outlined square
```

**Colorblind note.** In simulation (Machado 2009 matrices, CIEDE2000), no two of the 8 colors fall below a ΔE00 of 10.9, whether under protanopia, deuteranopia, tritanopia or normal vision. Every color has at least 3.1:1 contrast against the app background. The shapes still do half the work, so the pattern doesn't depend on color alone. This has not yet been checked on a real Prime screen. See `docs/colorblind.md`, which is reproducible with `tools/colorblind.py`.

## What the pattern does and doesn't do

The action code and the colored shapes help a *person* notice when the request on the Prime isn't the one their agent showed, for example if it was swapped or changed on the way. They are a convenience for spotting that, not the security boundary.

The real protection is on the agent. Before acting, the agent runs `verify_reply`: it rebuilds the signed message from its own request `id`, its own `kid` and the hash of the exact action it's about to run, checks the reply's signature over that against the pinned app key, and requires the decision to be approve. An agent that skips that check isn't protected by any pattern on the screen.

## Trusted frame

The Review screen has two app-only areas:
- **the band:** the paired name, the high-impact level (from the parsed action) and the paired check
- **the frame:** the summary and detail lines the Prime built from the parsed action (or "Unrecognized: tool"), action code, colored shapes and countdown

Nothing the agent writes freely (title, details) is ever drawn inside either one. That text only appears in the scrolling area between them.

What the frame means: the request is **verified from the paired agent, unchanged**, and for a known tool the summary is what the signed action bytes actually say, because the Prime parsed them itself. It does not mean the action is safe, and for an unknown tool it means only "read the raw action above".

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

**Scan code** opens the system QR scanner (this needs the `ShowModal` permission). A request scanned from the Launcher's own scanner is handed to the app through the `primeapprove:v2:` QR match rule and picked up at launch. Either way, the text goes through the same checks: size, signature, paired agent, plain-ASCII text, expiry no more than 10 minutes out, and single use. The simulator has no camera, so neither path can be exercised there.

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

- `src/proto.rs` has unit tests for the protocol: the glyph test vector, clear signing (a known tool shows the parsed fields, a lying title can't change the verb, object or target, the Prime computes the hash, an unknown tool gets the raw view and high impact, bad JSON and bad fields are rejected, v1 and extra request fields are refused), QR size, the compact reply (round trip, every single-bit tamper fails, wrong pinned key, wrong request hash, id or kid, 78-byte payload and QR version 5, base45 against RFC 9285, a fixed test vector), and one test per finding from the October 2026 review (plain-ASCII text, the expiry limit, high impact set from the parsed action). Pending-pairing tests check that nothing is saved without Codes match. Pairing tests cover the offer and answer roundtrip, a forged offer signature, a far-future expiry, name checks, the pairing code (same both ways, changes if either key or the Prime's nonce changes; a v1 answer or a malformed nonce is refused) and agent-side pinning (a reply from any other app key fails). Run them on any computer with `cd host-tests && cargo test` (no KeyOS SDK needed). The host tests also include the cross tests with the Python agent library (`host-tests/src/lib.rs`).
- `docs/colorblind.md`: the palette check behind the colorblind note.
- `tools/colorblind.py`: re-runs that check (needs numpy). `--old` shows the previous palette.
- `agent/`: the agent-side library and `pa` CLI (see *Agent CLI*), and the GitHub gate (`agent/primeapprove/gate.py`, see *GitHub gate*). `agent/tests/test_gate.py` runs the gate against a local fake GitHub API: approve posts success on the exact SHA, deny posts failure, a moved head, a wrong repo, a reused reply, an expired request, a strange signer, repeated or extra request fields and unknown tools are all refused, merge mode merges only the approved SHA, and with a moved head both the gate and (with the test-only pre-check skip) the fake GitHub's 409 refuse. The token never appears in output.
- `tools/decode_reply.py`: a wrapper around the agent library: `pa verify PHOTO`, or a check against explicit `--pubkey --id --kid --hash` values.
- `tools/*.sh`: simulator driving and screenshot scripts.
- `scripts/security_scan.sh`: a local, report-only secret and dependency scan (see *Security scan*). Its tests are `python3 scripts/test_security_scan.py`.

## Security scan

Before a change merges, run:

    scripts/security_scan.sh

The command only reports. It does not change code, git history, or git settings.

It scans every tracked text file in the working tree and the full git history for secrets, then audits each Rust `Cargo.lock` and the Python dependencies in `agent/`.

Each check ends in exactly one of three states:

| State | Meaning |
|---|---|
| **CLEAN** | The check finished and found nothing. |
| **FINDINGS** | The check finished and found a secret or a vulnerable dependency. A secret is reported as the rule, file, commit, and line, plus a fingerprint (the first 16 hex characters of the SHA-256 of the matched value). The value is not printed. A dependency is reported as the advisory id, package, version, and lockfile. |
| **SCAN INCOMPLETE** | The check did not finish, because the tool is missing, crashed, timed out, or its output could not be read. The scan leaves that check as SCAN INCOMPLETE. |

The process exits 0 when every check is CLEAN, 1 when at least one check is FINDINGS and none is SCAN INCOMPLETE, and 2 when any check is SCAN INCOMPLETE. Findings from checks that did finish are still printed when the exit code is 2.

`pip-audit` exits 1 when it finds vulnerabilities. That exit code is FINDINGS. An unreadable report, a crash, or a missing auditor is SCAN INCOMPLETE.

Secrets use `gitleaks` when it is on `PATH` (or in `~/.local/bin`), otherwise `trufflehog`, otherwise built-in patterns: GitHub tokens, Stripe keys, Google and AWS keys, private key blocks (Ed25519, OpenSSH, and other PEM), and high-entropy assignments. Rust lockfiles use `cargo audit` when it is installed, otherwise `osv-scanner`. Python dependencies in `agent/` use `pip-audit`, otherwise `osv-scanner` for a requirements file or lockfile. `pip install --user pip-audit` and the release binaries for `gitleaks` and `osv-scanner` do not need root. `cargo install cargo-audit` installs the Rust auditor.

## About the screenshots

The KeyOS simulator swaps the red and blue channels in its screenshots. The published screenshots have been color-corrected (R and B swapped back) so they match what the Prime actually shows. Raw simulator captures will look wrong.

## License

GPL-3.0-or-later. See `LICENSE`.
