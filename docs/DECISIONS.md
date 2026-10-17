# Decisions

## Decision v1.0 (2026-10-17): A. Keep the `prime-approve` check advisory on main.

Decided by Michael McClanahan (repo owner).

Make it required only when all five are true:

1. The build agent (tinkabot) uses its own GitHub credential with no admin rights, and the owner's gh login isn't reachable from its machine.
2. The gate runs on a machine or OS account the agent can't reach, and posts its status as its own GitHub App.
3. The required check is pinned to that App. Post one status as the App before adding the rule. A commit status is fine; no need to switch to check runs.
4. "Do not allow bypassing the above settings" is on.
5. Approvals come from a Prime the agent can't drive: not the simulator, and not a dev unit plugged into the agent's machine with Developer Mode on.

Until all five are true, main is not described as Prime-protected anywhere public.

Status on 2026-10-17: none of the five are met. The agent works through the owner's account with admin rights, the gate runs on the agent's machine with a personal token, and every approval so far came from the simulator, which the agent can drive (`tools/flow.sh`).
