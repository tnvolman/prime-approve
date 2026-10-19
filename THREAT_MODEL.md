# Prime Approve threat model

Status: **v0.7, simulator only.** Not yet run on Passport Prime hardware.

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
| Compromised agent skips approval | Open today (see docs/DECISIONS.md); mitigated when the gate runs off-agent and branch protection requires the check. Required check: off until all five conditions in DECISIONS.md are met | `pa gate` holds the token on another machine, account or CI job the agent can't edit; it posts the `prime-approve/<base>` status only on the approved head SHA, and only if the PR still targets the approved base (or merges with `sha=` that head, so GitHub returns 409 if it moved). Residual: repo admins can bypass branch protection; until the required check comes only from the gate's identity, any token with commit-status write access, including the agent's, can post a fake `prime-approve/<base>` success, so give the agent a fine-grained token without Commit statuses or merge rights, or have the gate post as its own GitHub App; the gate's token scope is the gate's blast radius; a gate on the agent's own account protects nothing |
| Tool name faked with `\u` escapes (e.g. a Cyrillic look-alike) | Blocked | No `\u` escapes anywhere in an action; tool names limited to `A-Z a-z 0-9 . _ -`, so the name shown is the raw text (Prime, `pa` and the gate share the parser and test cases) |
| PR retargeted to another branch after approval | Blocked (with the gate) | Since v0.7 the base branch is in the signed action, shown on the Prime ("Merge PR #2 into main"), checked by the gate against the PR's `base.ref` ("base moved" refusal), and the status context names the base (`prime-approve/<base>`), so an approval for `release` never satisfies a check required on `main`. Guarded by `agent/tests/test_review_base_branch.py` |
| PR retargeted in the moment before a merge-mode merge | Open (small window) | Merge mode re-checks the base right before the merge call, but GitHub's merge API can't check the base itself, so a retarget between that last check and the merge isn't caught. Status mode with the required `prime-approve/main` check has no such window |
| Approved, then a new commit pushed | Blocked (with the gate) | The status is posted on one SHA; a new head has none. Merge mode passes the approved SHA, so GitHub refuses a moved head. Shown live on PR #1 |
| Agent approves its own request (drives the simulator, or a Developer Mode dev unit plugged into its machine) | Open | Approvals must come from a Prime the agent can't drive; until then, simulator approvals are demo evidence only |
| Agent's GitHub credential has admin rights (today it works through the owner's account) | Open | Give the agent its own non-admin credential, keep the owner's gh login off its machine, and turn on "Do not allow bypassing the above settings" |
| Approver doesn't compare codes carefully | Partly mitigated | Action code plus shape row; clear-signing reduces reliance on comparison |
| Unattended unlocked Prime | Open | Short expiry. A KeyOS-drawn confirmation for high-impact approvals is unconfirmed by Foundation (asked 2026-10-17) |
| Lost Prime | Open | Key epoch in HKDF info ("app key v1" to v2) and unpairing at the agent or gate |
| Key swapped during pairing | Blocked | Pairing code from both keys and a fresh nonce the Prime picks for each pairing (v0.7), compared on both screens; saved only on "Codes match"; agent pins the Prime's key after its user confirms. The nonce makes every code single-use; it does not replace the comparison |
| Simulator approval mistaken for a real Prime's on GitHub | Mitigated | `pa gate-trust --simulator` marks the pinned key; the gate's status then says "Approved in simulator". Default is not simulator, so marking it is up to whoever pins the key |
| Unpaired agent keeps access | Blocked | Unpairing is saved and survives a restart; that agent's requests are refused |
| Pairing lost after a KeyOS update | Mitigated | Foundation says GetAppSeed is designed to stay stable across KeyOS updates (2026-10-19); confirm on hardware |
| Another app derives our app key (same app-id, different publisher) | Open | The app key is believed to derive from app-id plus master seed (not confirmed by Foundation), and Foundation confirmed (2026-10-19) that GetAppSeed does not bind the publisher key. Whether KeyOS lets a second publisher install an app with our app-id is unconfirmed; until it is, assume such an app could sign approvals as Prime Approve. Forks must change the app-id, and users should install only builds signed by our publisher key |

## Rules for anyone integrating

1. Pin the Prime's public key at pairing, only after your own user confirms the pairing codes match. Replies carry no key; verify every one against the pinned key.
2. Enforce single use and expiry where the credential lives.
3. Recompute the action hash from the exact action you will run, including the commit SHA, and verify the reply's signature over it. The reply never carries the full hash; it signs it, so only the agent's own recomputed hash verifies.
4. Don't let the agent hold the credential it is asking approval to use. Run the gate on a different machine or OS account (or a CI job the agent can't modify), with its own state dir, pinned keys and token.
5. Carry out known tools only. An approval of an action the Prime showed as "Unrecognized" is a person reading raw JSON, not something an executor should act on automatically.

## Answered by Foundation (2026-10-19)

- Security review checklist: none to share. KeyOS permissions limit which APIs an app can use but don't replace reviewing the app's own signing logic and threat model.
- GetAppSeed: designed to stay stable across KeyOS updates; does not bind the publisher key.
- QuantumLink: SDK apps are expected to use it over Bluetooth and/or USB starting with KeyOS 1.5.0, as a path beside QR codes.

## Open questions for Foundation

- Can an app from a different publisher install with an app-id already in use, and what exactly does GetAppSeed derive from?
- Is a KeyOS-drawn confirmation prompt for high-impact approvals planned?
- Can the simulator inject a Launcher QR handoff for testing?
