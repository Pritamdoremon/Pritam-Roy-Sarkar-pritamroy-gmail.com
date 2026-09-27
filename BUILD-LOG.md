# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

2026-09-27: Expected the JWT checks to fail because verification was still a stub. Found that
stale permission versions are checked separately by `assertFresh()`, which needs the current
membership. Implemented token structure, header, signature, expiry, issuer, audience, and `jti`
checks in `verifyAccessToken()`. `node scripts/check-jwt.js`: 43 passed, 0 failed. The JWT test
does not exercise stale-version comparison; that remains the responsibility of `assertFresh()`.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

2026-09-27 (Task 2 — caller authentication): Expected authentication/context checks to fail
while `authenticate()` was still a stub. Observed: the focused context smoke test covered valid
context, missing token, cross-org `404`, suspended membership, and stale permission version.
Changed: implemented `authenticate()` with token verification, current user and membership
lookups, organization isolation, suspended-member rejection, and stale-version validation.
Test: focused context smoke check — 5 passed, 0 failed. `node scripts/check-api.js` did not
reach API assertions because `scripts/load-db.js` exited with status 1.

2026-09-27: Expected the documented role list to be insufficient for the permission catalogue.
The personalization check confirmed this with role `duty_manager` and permission `session:record`.
Loaded permissions, memberships, baselines, and active grants from the database, and resolved
device results before building the organization-level union. `check-permissions.js`: 35 passed,
0 failed; `check-personalisation.js`: 18 passed, 0 failed.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

2026-09-27 (Task 4 — API integration): Expected `check-api.js` to expose the missing route
behavior. Observed: `server/routes/index.js` registered none, and the first check stopped before
API assertions because `scripts/load-db.js` formed an invalid Windows path from `URL.pathname`.
Changed: converted script URLs with `fileURLToPath`, registered the API handlers, and connected
them to context, permissions, lifecycle, and audit helpers. `node scripts/check-api.js`: 66
passed, 0 failed.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
