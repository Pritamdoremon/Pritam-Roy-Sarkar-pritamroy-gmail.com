// End-to-end API check. Spawns the server against a throwaway database, drives the real
// HTTP contract, and asserts on behaviour rather than on implementation.
//
//   node scripts/check-api.js
//
// This is the seed of the public test suite. It is deliberately dependency-free so it
// can run before Playwright is installed.

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';

const PORT = 8123;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-api.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'test-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

await new Promise((r) => setTimeout(r, 1200));

// Abort cleanly: if a check below throws (an unimplemented API returns a body with no
// fields on it), take the server down with us instead of leaving it holding the port.
for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, (err) => {
    console.error(`\n  aborted: ${err?.message ?? err}`);
    server.kill();
    process.exit(1);
  });
}
let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;

  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, body: json, raw: text, setCookie: res.headers.get('set-cookie') };
}

const login = (email, orgId, password = 'demo1234') =>
  call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } });

// ---------------------------------------------------------------------------
console.log('\n== auth and org scoping ==');
const dana = await login('dana@example.test');
check('dana logs in', dana.status, 200);
check('dana is owner in Acme', dana.body.role, 'owner');
check('dana sees both orgs', dana.body.orgs.map((o) => o.name).sort(), ['Acme Robotics', 'Globex Industries']);
check('org themes differ', new Set(dana.body.orgs.map((o) => o.theme)).size, 2);

const danaAcme = dana.body.token;
check('bad password rejected', (await call('POST', '/auth/login', { body: { email: 'dana@example.test', password: 'wrong' } })).status, 401);
check('no token -> 401', (await call('GET', '/orgs/org_acme/devices')).status, 401);

console.log('\n== §6 cross-org is INVISIBLE, not forbidden ==');
const xorg = await call('GET', '/orgs/org_globex/devices', { token: danaAcme });
check('Acme token against Globex -> 404', xorg.status, 404);
check('  ...code is NOT_FOUND', xorg.body.error.code, 'NOT_FOUND');
check('  ...body carries no org data', JSON.stringify(xorg.body).includes('globex-desk'), false);

console.log('\n== §7.4 same login, different role per org ==');
const sw = await call('POST', '/auth/token', { token: danaAcme, body: { orgId: 'org_globex' } });
check('switch to Globex', sw.status, 200);
check('  ...role is viewer there', sw.body.role, 'viewer');
const danaGlobex = sw.body.token;

const globexDevices = await call('GET', '/orgs/org_globex/devices', { token: danaGlobex });
const byName = Object.fromEntries(globexDevices.body.devices.map((d) => [d.name, d.permissions]));
check('D6 grant unlocks control on ONE device', byName['globex-desk-01']['device:control'].effect, 'allow');
check('  ...and stays locked on the other', byName['globex-kiosk-02']['device:control'].effect, 'deny');
check('  ...provenance names the grant', byName['globex-desk-01']['device:control'].source.startsWith('grant:'), true);

console.log('\n== §3 auditor/operator are NOT ordered (D2) ==');
const samAcme = (await login('sam@example.test')).body.token;
const samGlobex = (await call('POST', '/auth/token', { token: samAcme, body: { orgId: 'org_globex' } })).body.token;
check('Acme(operator)  GET /audit  -> 403', (await call('GET', '/orgs/org_acme/audit', { token: samAcme })).status, 403);
check('Globex(auditor) GET /audit  -> 200', (await call('GET', '/orgs/org_globex/audit', { token: samGlobex })).status, 200);
check('Acme(operator)  control session -> 201', (await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'control' } })).status, 201);
check('Globex(auditor) control session -> 403', (await call('POST', '/orgs/org_globex/sessions', { token: samGlobex, body: { deviceId: 'dev_globex_desk_01', mode: 'control' } })).status, 403);

console.log('\n== §2 device:list gates the endpoint, device:view gates ROW INCLUSION ==');
const viewer = (await login('viewer@acme.test')).body.token;
const vDevices = await call('GET', '/orgs/org_acme/devices', { token: viewer });
const vNames = vDevices.body.devices.map((d) => d.name);
check('kiosk-lobby-01 is ABSENT (not redacted)', vNames.includes('kiosk-lobby-01'), false);
check('the others are present', vNames.length, 4);

console.log('\n== §9 compound session check, two distinct reasons ==');
const s1 = await call('POST', '/orgs/org_acme/sessions', { token: viewer, body: { deviceId: 'dev_lab_mac_01', mode: 'view' } });
check('viewer CAN view lab-mac-01 (grant)', s1.status, 201);
const s2 = await call('POST', '/orgs/org_acme/sessions', { token: viewer, body: { deviceId: 'dev_qa_android_01', mode: 'view' } });
check('...but not qa-android-01', s2.status, 403);
check('  ...reason: missing session:start', s2.body.error.reason, 'missing_permission');
const s3 = await call('POST', '/orgs/org_acme/sessions', { token: viewer, body: { deviceId: 'dev_lab_mac_01', mode: 'control' } });
check('  ...and control fails differently', s3.body.error.reason, 'missing_device_permission');

console.log('\n== D10 exclusive sessions; view is deliberately not ==');
const dup = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'control' } });
check('2nd control on same device -> 409', dup.status, 409);
check('  ...code DEVICE_BUSY', dup.body.error.code, 'DEVICE_BUSY');
const v1 = await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_win_01', mode: 'view' } });
check('concurrent VIEW on same device -> 201', v1.status, 201);

console.log('\n== §7.1 GRANDFATHERING: permission change does not kill a session ==');
const active = (await call('GET', '/orgs/org_acme/sessions', { token: samAcme })).body.sessions
  .filter((s) => s.state === 'active' && s.mode === 'control' && s.device_id === 'dev_lab_win_01');
const heldId = active[0].id;
const demote = await call('PATCH', '/orgs/org_acme/members/usr_sam', { token: danaAcme, body: { role: 'viewer' } });
check('owner demotes Sam to viewer', demote.status, 200);
const stillThere = await call('GET', `/sessions/${heldId}`, { token: danaAcme });
check('  ...the live session SURVIVES', stillThere.body.state, 'active');
check('  ...end_reason is still null', stillThere.body.end_reason, null);
check('  ...but a NEW session is now blocked (for Sam)', (await call('POST', '/orgs/org_acme/sessions', { token: samAcme, body: { deviceId: 'dev_lab_mac_01', mode: 'control' } })).status, 401);
check('  ...Sam\'s stale token -> 401 TOKEN_STALE', (await call('GET', '/orgs/org_acme/devices', { token: samAcme })).body.error.code, 'TOKEN_STALE');

console.log('\n== §7.2 suspension DOES cascade (account integrity, not a permission tweak) ==');
// Sam still OWNS the control session created above. Suspend Sam, not the viewer.
await call('POST', '/orgs/org_acme/members/usr_sam/suspend', { token: danaAcme });
const afterSuspend = await call('GET', `/sessions/${heldId}`, { token: danaAcme });
check('suspended user\'s session ended', afterSuspend.body.state, 'ended');
check('  ...end_reason user_suspended', afterSuspend.body.end_reason, 'user_suspended');
check('reinstate restores access', (await call('DELETE', '/orgs/org_acme/members/usr_sam/suspend', { token: danaAcme })).status, 200);

console.log('\n== D8 modification authority ==');
check('no self role change', (await call('PATCH', '/orgs/org_acme/members/usr_dana', { token: danaAcme, body: { role: 'admin' } })).body.error.code, 'SELF_ROLE_CHANGE');
// Acme has two owners, so demoting one is legitimate. The LAST_OWNER guard needs an org
// with exactly one owner — a freshly created org has exactly one, its creator.
const fresh = await call('POST', '/orgs', { token: danaAcme, body: { name: 'Solo Org' } });
check('create org makes the creator sole owner', fresh.body.role, 'owner');
// D18: the Acme-scoped token cannot address the new org AT ALL. This 404s before any
// permission check runs, which is the structural isolation guarantee, not a filter.
check('D18 Acme token cannot address the new org', (await call('DELETE', `/orgs/${fresh.body.id}/members/me`, { token: danaAcme })).status, 404);
const freshTok = (await call('POST', '/auth/token', { token: danaAcme, body: { orgId: fresh.body.id } })).body.token;
check('sole owner cannot leave (LAST_OWNER)', (await call('DELETE', `/orgs/${fresh.body.id}/members/me`, { token: freshTok })).body.error.code, 'LAST_OWNER');
check('demoting a NON-last owner is allowed', (await call('PATCH', '/orgs/org_acme/members/usr_acme_owner', { token: danaAcme, body: { role: 'viewer' } })).status, 200);
const adminTok = (await login('admin@acme.test')).body.token;
check('admin cannot confer owner', (await call('PATCH', '/orgs/org_acme/members/usr_acme_viewer', { token: adminTok, body: { role: 'owner' } })).body.error.code, 'FORBIDDEN');

console.log('\n== D19 unknown permission is rejected ==');
const badGrant = await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['device:teleport'] } });
check('device:teleport -> 400', badGrant.status, 400);
check('  ...reason unknown_permission', badGrant.body.error.reason, 'unknown_permission');
const emptyGrant = await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: [] } });
check('empty permissions -> 400', emptyGrant.status, 400);
check('self-grant forbidden (D9)', (await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_dana', effect: 'allow', permissions: ['audit:read'] } })).body.error.code, 'FORBIDDEN');

console.log('\n== invites: single-use, hashed, no data leak ==');
const inv = await call('POST', '/orgs/org_acme/invites', { token: danaAcme, body: { email: 'newbie@example.test', role: 'operator' } });
check('invite created', inv.status, 201);
check('raw token returned once', typeof inv.body.inviteToken === 'string' && inv.body.inviteToken.length > 20, true);
const rawToken = inv.body.inviteToken;

const peek = await call('GET', `/invites/${rawToken}`);
check('public peek works', peek.status, 200);
check('  ...shows org name', peek.body.orgName, 'Acme Robotics');
check('  ...leaks NO devices', JSON.stringify(peek.body).includes('lab-mac'), false);
check('  ...leaks NO org id', JSON.stringify(peek.body).includes('org_acme'), false);
check('unknown token -> 404', (await call('GET', '/invites/not-a-real-token-at-all-xxxx')).status, 404);

const accept = await call('POST', `/invites/${rawToken}/accept`, { body: { name: 'New Bie', password: 'hunter2hunter2' } });
check('accept succeeds', accept.status, 200);
check('  ...role is the invited role', accept.body.role, 'operator');
check('reuse -> 409', (await call('POST', `/invites/${rawToken}/accept`, { body: { name: 'X', password: 'hunter2hunter2' } })).status, 409);
check('new user can log in', (await login('newbie@example.test', null, 'hunter2hunter2')).status, 200);
check('  ...and cannot log in with the seed password', (await login('newbie@example.test')).status, 401);

console.log('\n== audit records DENIED attempts too ==');
const audit = await call('GET', '/orgs/org_acme/audit?limit=200', { token: danaAcme });
check('audit readable by owner', audit.status, 200);
check('  ...contains denials', audit.body.events.some((e) => e.result === 'deny'), true);
check('  ...denial carries a reason code', audit.body.events.some((e) => e.result === 'deny' && e.reason_code), true);

console.log('\n== pagination boundaries are defined, not clamped ==');
for (const [q, expected] of [['limit=0', 400], ['limit=-1', 400], ['limit=99999', 400], ['offset=-1', 400], ['offset=99999', 200], ['limit=1', 200]]) {
  check(`audit?${q} -> ${expected}`, (await call('GET', `/orgs/org_acme/audit?${q}`, { token: danaAcme })).status, expected);
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
server.kill();
process.exit(fail === 0 ? 0 : 1);
