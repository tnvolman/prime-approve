# Prime Approve threat model

Status: draft for v0.2. Simulator-tested only, not yet run on Passport Prime hardware.

## What Prime Approve is for

A person approves or denies one exact action an AI agent wants to take, on a screen that no software the agent can reach is able to draw. Examples are merging to a protected branch, a production deploy, or a payment.

## What the Prime proves

When the Prime shows a request inside the bordered panel and the person slides to approve, the signed reply proves three things:

1. The request was signed by an agent key this Prime has paired with.
2. The request was not changed after the agent signed it.
3. A person holding this unlocked Prime approved that request ID and action hash before it expired.

## What the Prime does not prove

- **That the action is safe.** The Prime shows what it was sent.
- **That the agent's summary matches the action,** until the Prime reads the action itself (planned). Until then the summary line is agent-supplied, limited to a fixed list of action words and short checked fields.
- **That the approval will be honored.** Whatever holds the credential decides that. If the agent holds it, a compromised agent can skip the approval entirely.
- **Who was holding the device.** Third-party KeyOS apps can't ask for the PIN again, so an unlocked, unattended Prime can approve.

## Trust boundaries

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Passport Prime + Prime Approve | Showing the request as received, checking the signature, signing the decision | Knowing what the action really does (until clear-signing lands) |
| Agent | Proposing actions | Describing its own action honestly, enforcing its own approval |
| Laptop showing the QR | Carrying bytes | Anything else; it may be compromised |
| Gate (planned) | Holding the credential, checking the reply, pinning the exact commit | Nothing the agent tells it |

## Threats and status

| Threat | Status | Mitigation |
| --- | --- | --- |
| Tampered request | Blocked | Ed25519 signature checked before parsing, domain-separated |
| Unknown agent | Blocked | Lookup by key id against paired keys |
| Replay of an old approval | Blocked by the agent or gate | Single-use IDs and expiry enforced where the credential lives; Prime also remembers 512 answered IDs |
| Far-future expiry | Fix in v0.2 | Reject expiry more than 10 minutes out |
| Hidden or look-alike text | Fix in v0.2 | Allow only printable ASCII (plus newline in details) |
| Agent hides risk | Fix in v0.2 | "High impact" set from the action word, not by the agent |
| Public demo key trusted on a device | Fix in v0.2 | Demo key behind a build flag, off by default, with a visible warning |
| Agent describes one action and hashes another | Open | Prime parses the action and computes the hash (clear-signing) |
| Compromised agent skips approval | Open | Gate on a separate machine holds the credential; GitHub enforces via required check or deployment protection rule |
| Approver doesn't compare codes carefully | Partly mitigated | Action code plus shape row; clear-signing reduces reliance on comparison |
| Unattended unlocked Prime | Open | Short expiry; ask Foundation about a KeyOS-drawn confirmation for high-impact approvals |
| Lost Prime | Open | Key epoch in HKDF info ("app key v1" to v2) and unpairing at the agent or gate |
| Fork reuses our app-id | Documented | The app key derives from app-id plus master seed; forks must change the app-id |

## Rules for anyone integrating

1. Pin the Prime's public key at pairing. Never trust the key a reply carries.
2. Enforce single use and expiry where the credential lives.
3. Recompute the action hash from the exact action you will run, including the commit SHA, and compare it with the reply.
4. Don't let the agent hold the credential it is asking approval to use.

## Open questions for Foundation

- Will the GetAppSeed derivation stay stable across KeyOS updates, and will it bind the publisher key?
- Is there a planned path for third-party apps to use QuantumLink data, or a KeyOS-drawn confirmation prompt?
- Can the simulator inject a Launcher QR handoff for testing?
