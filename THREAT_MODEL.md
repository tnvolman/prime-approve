# Prime Approve threat model

Status: draft for v0.5. Simulator-tested only, not yet run on Passport Prime hardware.

## What Prime Approve is for

A person approves or denies one exact action an AI agent wants to take, on a screen that no software the agent can reach is able to draw. Examples are merging to a protected branch, a production deploy, or a payment.

## What the Prime proves

When the Prime shows a request inside the bordered panel and the person slides to approve, the signed reply proves three things:

1. The request was signed by an agent key this Prime has paired with.
2. The request was not changed after the agent signed it.
3. A person holding this unlocked Prime approved that request ID and action hash before it expired.

## What the Prime does not prove

- **That the action is safe.** The Prime shows what it was sent.
- **That an unknown action is what it looks like.** Since v0.5 the Prime reads the action bytes itself and builds the summary line for known tools (`github.merge_pull_request`). Anything else is shown raw, marked "Unrecognized action, read carefully" and high impact; the person has to read it. The agent's title and details are still just claims ("Agent says").
- **That the approval will be honored.** Whatever holds the credential decides that. If the agent holds it, a compromised agent can skip the approval entirely. The GitHub gate (`pa gate`, v0.6) is the piece that honors it: it holds the token, runs off-agent, and marks or merges only the exact approved head SHA.
- **Who was holding the device.** Third-party KeyOS apps can't ask for the PIN again, so an unlocked, unattended Prime can approve.

## Trust boundaries

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Passport Prime + Prime Approve | Showing the request as received, checking the signature, signing the decision | Knowing what an unknown tool's action really does (shown raw), or what a known tool does beyond its parsed fields |
| Agent | Proposing actions | Describing its own action honestly, enforcing its own approval |
| Laptop showing the QR | Carrying bytes | Anything else; it may be compromised |
| Gate (`pa gate`, run off-agent) | Holding the GitHub token, checking the request and reply against keys it pinned itself, single use and expiry in its own store, pinning the exact commit | Nothing the agent tells it beyond the signed request; it never rebuilds the action from fields, and refuses unknown tools |

## Threats and status

| Threat | Status | Mitigation |
| --- | --- | --- |
| Tampered request | Blocked | Ed25519 signature checked before parsing, domain-separated |
| Unknown agent | Blocked | Lookup by key id against paired keys |
| Replay of an old approval | Blocked by the agent or gate | Single-use IDs and expiry enforced where the credential lives; Prime also remembers 512 answered IDs |
| Far-future expiry | Blocked | Reject expiry more than 10 minutes out |
| Hidden or look-alike text | Blocked | Allow only printable ASCII (plus newline in details) |
| Agent hides risk | Blocked | "High impact" set by the Prime from the parsed action (always for unknown tools), never by the agent |
| Public demo key trusted on a device | Blocked | Demo key behind a build flag, off by default, with a visible warning |
| Agent describes one action and hashes another | Blocked | Prime parses known actions and computes the hash; unknown actions shown raw and marked high impact |
| Compromised agent skips approval | Mitigated when the gate runs off-agent and branch protection requires the check | `pa gate` holds the token on another machine, account or CI job the agent can't edit; it posts the `prime-approve` status only on the approved head SHA (or merges with `sha=` that head, so GitHub returns 409 if it moved). Residual: repo admins can bypass branch protection; until the required check comes only from the gate's identity, any token with commit-status write access, including the agent's, can post a fake `prime-approve` success, so give the agent a fine-grained token without Commit statuses or merge rights, or have the gate post as its own GitHub App; the gate's token scope is the gate's blast radius; a gate on the agent's own account protects nothing |
| Tool name faked with `\u` escapes (e.g. a Cyrillic look-alike) | Blocked | No `\u` escapes anywhere in an action; tool names limited to `A-Z a-z 0-9 . _ -`, so the name shown is the raw text (Prime, `pa` and the gate share the parser and test cases) |
| Approved, then a new commit pushed | Blocked (with the gate) | The status is posted on one SHA; a new head has none. Merge mode passes the approved SHA, so GitHub refuses a moved head. Shown live on PR #1 |
| Agent drives the Prime itself (simulator, or a dev unit on its machine in Developer Mode) | Open | `foundation-passport-drive` can tap approve; real approvals must come from a Prime the agent can't drive. See docs/DECISIONS.md |
| Agent holds admin on the repo | Open | An admin can remove or bypass the required check; the agent needs its own credential without admin rights. See docs/DECISIONS.md |
| Approver doesn't compare codes carefully | Partly mitigated | Action code plus shape row; clear-signing reduces reliance on comparison |
| Unattended unlocked Prime | Open | Short expiry; ask Foundation about a KeyOS-drawn confirmation for high-impact approvals |
| Lost Prime | Open | Key epoch in HKDF info ("app key v1" to v2) and unpairing at the agent or gate |
| Key swapped during pairing | Blocked | Pairing code from both keys, compared on both screens; saved only on "Codes match"; agent pins the Prime's key after its user confirms |
| Unpaired agent keeps access | Blocked | Unpairing is saved and survives a restart; that agent's requests are refused |
| Fork reuses our app-id | Documented | The app key derives from app-id plus master seed; forks must change the app-id |

## Rules for anyone integrating

1. Pin the Prime's public key at pairing, only after your own user confirms the pairing codes match. Replies carry no key; verify every one against the pinned key.
2. Enforce single use and expiry where the credential lives.
3. Recompute the action hash from the exact action you will run, including the commit SHA, and verify the reply's signature over it. The reply never carries the full hash; it signs it, so only the agent's own recomputed hash verifies.
4. Don't let the agent hold the credential it is asking approval to use. Run the gate on a different machine or OS account (or a CI job the agent can't modify), with its own state dir, pinned keys and token.
5. Carry out known tools only. An approval of an action the Prime showed as "Unrecognized" is a person reading raw JSON, not something an executor should act on automatically.

## Open questions for Foundation

- Will the GetAppSeed derivation stay stable across KeyOS updates, and will it bind the publisher key?
- Is there a planned path for third-party apps to use QuantumLink data, or a KeyOS-drawn confirmation prompt?
- Can the simulator inject a Launcher QR handoff for testing?
