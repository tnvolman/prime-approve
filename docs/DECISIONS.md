# Decisions

## Decision v1.0 (2026-10-17)

Decided by Michael McClanahan (repo owner). His words, unchanged:

```text
Decision v1.0 (2026-10-17): A. Keep the prime-approve check advisory on main.

Make it required only when all five are true:
1. tinkabot uses its own GitHub credential with no admin rights, and my gh login isn't reachable from its machine.
2. The gate runs on a machine or OS account tinkabot can't reach, and posts its status as its own GitHub App.
3. The required check is pinned to that App. Post one status as the App before adding the rule. A commit status is fine; no need to switch to check runs.
4. "Do not allow bypassing the above settings" is on.
5. Approvals come from a Prime tinkabot can't drive: not the simulator, and not a dev unit plugged into its machine with Developer Mode on.

Also fix README line 225: GitHub can tie a commit status to an app and block a same-named status from anyone else.
Until all five are true, don't describe main as Prime-protected anywhere public.
```

tinkabot is the agent that builds this repo.

Status on 2026-10-17: none of the five are met. The agent works through the owner's account with admin rights, the gate runs on the agent's machine with a personal token, and every approval so far came from the simulator, which the agent can drive (`tools/flow.sh`).
