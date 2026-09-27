# RemoteOps — Q1 starter

A multi-org permission console. One process, one port, one command.

This file describes the repository you were given: how to run it, what is already done, what is
yours to write, the guarantees the database already provides, and the attributes the console has
to carry.

## Run it

```sh
npm install
npm run db:reset     # schema + reference data + demo fixture
npm run dev          # http://localhost:8080
```

`npm run dev` is a single Node process: `node:http` serves `/v1/*` and hosts Vite in middleware
mode for the SPA. There is no second server, and there is no CORS.

```sh
npm run build        # vite build -> dist/
npm start            # one process, production mode
```

## Test it

```sh
node scripts/check-permissions.js   # the resolution engine
node scripts/check-jwt.js           # token verification — you implement this
node scripts/check-api.js           # the HTTP contract
npx playwright test                 # the console contract
```

The first three need only `better-sqlite3`. Playwright needs `npx playwright install chromium`
once.

`check-jwt.js` fails until you implement `verifyAccessToken` in `server/auth.js` — that function
is a stub. `check-api.js` and the UI suite fail with it, because every authenticated request
depends on it. Implement it first.

These suites are the floor, not the grade. They cover the happy path and the obvious failures;
we grade on a separate set that goes after the awkward cases.

---

## Layout

**Given.** Read these. They're the plumbing, not the exercise.

```
db/schema.sql        SQLite schema. STRICT tables, partial unique indexes, audit triggers.
db/reference.sql     The 5 roles, the 19 permissions, the role baselines.
seed/orgs.json       Demo fixture, with relative timestamps so it never goes stale.

server/
  index.js           the request pipeline, and static/Vite serving
  router.js          ~35 lines. the whole routing story.
  http.js            error types, body reading, response writing
  db.js              connection + the four PRAGMAs
  auth.js            JWT + scrypt, hand-rolled on node:crypto. Signing is done.
```

**Yours to write.** Everything below is missing or stubbed. This is the task.

```
server/
  auth.js            implement `verifyAccessToken` — the token verifier
  context.js         token -> caller, with structural org isolation
  permissions.js     the resolution engine — the only place allow/deny is decided
  lifecycle.js       role ranks, last-owner, ending sessions
  audit.js           append-only audit writes
  routes/            orgs, members, invites, devices, grants, sessions, audit

web/                 the React SPA
```

---

## The one thing that will bite you

```js
db.pragma('foreign_keys = ON');    // per connection. off by default.
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('synchronous = NORMAL');
```

`PRAGMA foreign_keys` is per-connection and off by default. Without it, every `REFERENCES`
clause in the schema is inert and the database enforces nothing. The schema still loads
perfectly, which is what makes it dangerous.

The worst casualty is the foreign key on `grant_permissions`, the one that rejects an unknown
permission string. With foreign keys off, `device:teleport` inserts happily and that validation
is silently gone. Verified both ways: with them off the insert succeeds, with them on it raises
`FOREIGN KEY constraint failed`.

---

## What the database already guarantees

You don't need application logic for any of these. They're verified against SQLite 3.43, under
concurrency, and they're yours to rely on.

| Guarantee | Enforced by |
|---|---|
| An unknown permission string is rejected | the `grant_permissions` FK, via `permission_patterns` |
| The audit log cannot be changed or deleted | `BEFORE UPDATE` / `BEFORE DELETE` triggers |
| One exclusive session per device | a partial unique index (`view` deliberately excluded) |
| One live invite per email | a partial unique index |
| Emails are lowercase | `CHECK (email = lower(email) COLLATE BINARY)` |

That last one is load-bearing in a subtle way: without `COLLATE BINARY`, the column's own
`COLLATE NOCASE` leaks into the `=` inside the check, the comparison is always true, and the
constraint never fires. It was caught by running it, not by reading it.

Where you can hand an invariant to the database instead of checking for it first in code, do.
Check-then-act races; a unique index doesn't.

---

## Two rules that shape the whole design

**1. There is exactly one permission resolution engine, and it is on the server.**

`server/permissions.js` is the only file that decides allow versus deny. There is no
role-to-permission table in `web/` at all — the console renders `data-state` from the resolved
permissions the API returns, and each device row carries its own resolved set. If you find
yourself writing `if (role === 'admin')` in `web/`, that is the bug.

The test that enforces this: intercept the API response, make the server say `deny`, and the
console must follow. A hardcoded client matrix keeps rendering `unlocked` and fails.

**2. Sessions are grandfathered.**

A session's authority is snapshotted when it starts and never changes. Revoking a grant or
changing a role blocks the **next** session but doesn't terminate one in flight. Every session
carries an `expires_at`, and that TTL is what stops "never terminated by a permission change"
from becoming "never terminated at all".

Suspension, membership removal and device transfer **do** cascade, because those are tenancy
events rather than permission tweaks.

One legitimate consequence: a device row can read `active` in Sessions while its Control button
is absent from the device row. Those are different questions. Don't reconcile them.

---

## Speed

The console should feel immediate on a laptop with the fixture loaded. First screen and first
authenticated request inside a second or so; switching orgs doesn't stall; nothing gets slower as
orgs, devices or members are added.

The usual causes, so you can avoid them deliberately:

- a list endpoint issuing one query per row
- resolving permissions more than once in a single request
- the console making a follow-up request per device to learn what it may do

The device-row shape exists to remove that last one. If you cache resolved permissions, the cache
must not be able to serve authority that has gone stale — version counters or short TTLs, and a
sentence in your notes explaining why it holds.

---

## The console contract

Design it however you like. These attributes are what the tests read, so they're fixed:

```html
<div    data-testid="app-shell"   data-org-id="org_acme" data-org-theme="cobalt">
<button data-testid="org-option"  data-org-id="org_globex">
<tr     data-testid="device-row"  data-device-id="dev_lab_mac_01">
<tr     data-testid="user-row"    data-user-id="usr_sam">
<button data-permission="device:control" data-state="unlocked">
<button data-testid="nav-audit"   data-permission="audit:read" data-state="unlocked">
```

An element is either present or absent — never disabled. If the caller holds the permission it is
rendered with `data-state="unlocked"`; if they don't, it is not in the DOM at all. Granting a
permission makes the element appear. Which elements exist at each permission level is fixed; the
attributes above are what the tests read.

---

## The demo fixture

One login, two organizations, visibly different views.

| User | Acme Robotics | Globex Industries |
|---|---|---|
| `dana@example.test` | **owner** | **viewer** |
| `sam@example.test` | **operator** | **auditor** |
| `owner@acme.test` | owner | — |
| `admin@acme.test` | admin | — |
| `viewer@acme.test` | viewer | — |
| `owner@globex.test` | — | owner |

Password for all: `demo1234`.

**Sam is the interesting one.** In Acme she's an operator: she can control devices, and she can't
read the audit log. In Globex she's an auditor: she can read the audit log, and she can't control
anything. Same person, and the two items swap — Control present in Acme and gone in Globex, the
Audit card the other way round. That's what it means for roles to be bundles rather than levels,
and it's why `roles.rank` must never answer a permission question.

The four seeded grants each demonstrate a different rule; read the `_demonstrates` field in
`seed/orgs.json`.

---

## Deliberately not here

Rate limiting. Email delivery — invite tokens are returned in the API response instead. Password
reset. Anything from Q2. Multi-region anything.

---

## A note on hidden tests

`seed/orgs.json` is published, so anything built on a published id is special-casable. The hidden
tests mint their own randomized orgs and tear them down. This fixture is for manual exploration
and the live demo.

---

## Your database is personalised

`npm run db:reset` loads the documented fixture **plus one organization generated for
you** from a nonce in `.candidate-nonce`. That organization contains:

- a role that appears in none of the documents
- a permission that appears in none of the documents
- a per-candidate baseline for that role
- a device-scoped `allow` and a device-scoped `deny` of that permission, on two
  different devices of the same org

The documented two organizations, their users, devices, grants and memberships are
untouched, so every shipped suite stays calibrated.

**This is the point.** The prose in this repository describes the model but is not the
model: the database is. Read `roles`, `permissions`, `role_permissions`,
`permission_patterns` and `grants` at runtime. An implementation that encodes the
documented 5-role / 19-permission matrix will pass the public suites and fail grading —
grading runs with a *different* nonce, so the values you can read in
`scripts/personalise.js` are not the values you will be graded on.

```sh
npm run fingerprint       # print the overlay generated from your nonce
npm run personalisation   # exercise YOUR engine against it
```

`scripts/check-personalisation.js` is a floor, not the grade. It is the same *shape* as
the graded check, with different values.


---

## What you must write up — 30% of the grade

Three artifacts are graded: the code (50%), `BUILD-LOG.md` + `DECISIONS.md` (30%), and a live
walkthrough (20%) drawn from your own log.

```sh
DISCOVERY-BRIEF.md   # what the write-up has to contain. read before you start.
BUILD-LOG.md         # append as you go, and commit as you go
DECISIONS.md         # one section per decision, including the alternative you rejected
```

The one rule that matters: **`BUILD-LOG.md` grows alongside the code, in its own commits.** A log
that arrives in one commit at the end is a story, and it is scored as one. Write down the moment
you were wrong while you are still wrong.

Expect to defend it live: to open the line that makes a decision, to take an alternative you
rejected, and to change your own code without assistance.
