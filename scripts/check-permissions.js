// Exercises the resolution engine against the real schema and the real seed fixture.
// Every case here is a vector from PERMISSIONS.md §11 or §12. Run: node scripts/check-permissions.js

import { readFileSync } from 'node:fs';
import { openDatabase, nowIso, bumpPermVersion, newId } from '../server/db.js';
import { resolve, can, assertCanStartSession } from '../server/permissions.js';

// Build a throwaway DB from the real schema + reference data.
const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));

const seed = JSON.parse(readFileSync(new URL('../seed/orgs.json', import.meta.url), 'utf8'));
const at = (offset) => {
  if (!offset) return null;
  const m = /^([+-])(\d+)([dhm])$/.exec(offset);
  if (!m) return offset;
  const mult = { d: 864e5, h: 36e5, m: 6e4 }[m[3]];
  return new Date(Date.now() + (m[1] === '-' ? -1 : 1) * Number(m[2]) * mult).toISOString();
};

for (const o of seed.organizations)
  db.prepare('INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES (?,?,?,?)')
    .run(o.id, o.name, o.theme, o.maxSessionMinutes);
for (const u of seed.users)
  db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)')
    .run(u.id, u.email.toLowerCase(), u.name, 'x');
for (const m of seed.memberships)
  db.prepare('INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,?,?,?)')
    .run(newId('mem'), m.orgId, m.userId, m.role, m.status, at(m.joinedAt));
for (const d of seed.devices)
  db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)')
    .run(d.id, d.orgId, d.name, d.kind, d.online ? 1 : 0);
for (const g of seed.grants) {
  db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by) VALUES (?,?,?,?,?,?,?,?)')
    .run(g.id, g.orgId, g.userId, g.deviceId ?? null, g.effect, at(g.startsAt), at(g.expiresAt), g.createdBy);
  for (const p of g.permissions)
    db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run(g.id, p);
}

// --- tiny assertion harness -------------------------------------------------
let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(58)} ${ok ? '' : `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};
const effect = (userId, orgId, permission, deviceId = null) =>
  resolve(db, { userId, orgId, deviceId }).permissions[permission].effect;
const reason = (userId, orgId, permission, deviceId = null) =>
  resolve(db, { userId, orgId, deviceId }).permissions[permission].reason;

const A = 'org_acme', G = 'org_globex';

console.log('\n== PERMISSIONS.md §3 — role baselines ==');
check('owner: device:control', effect('usr_acme_owner', A, 'device:control'), 'allow');
check('admin: org:delete DENIED', effect('usr_acme_admin', A, 'org:delete'), 'deny');
check('viewer: device:control denied', effect('usr_acme_viewer', A, 'device:control'), 'deny');
check('viewer: device:control reason=implicit', reason('usr_acme_viewer', A, 'device:control'), 'implicit');

console.log('\n== §3 — auditor/operator are NOT ordered (D2) ==');
check('auditor(sam@globex): audit:read  ALLOW', effect('usr_sam', G, 'audit:read'), 'allow');
check('auditor(sam@globex): device:control DENY', effect('usr_sam', G, 'device:control'), 'deny');
check('operator(sam@acme):  audit:read  DENY', effect('usr_sam', A, 'audit:read'), 'deny');
check('operator(sam@acme):  device:control ALLOW', effect('usr_sam', A, 'device:control'), 'allow');

console.log('\n== §11 vector 3 — a grant is device-scoped (D6) ==');
check('viewer: session:start on lab-mac-01', effect('usr_acme_viewer', A, 'session:start', 'dev_lab_mac_01'), 'allow');
check('viewer: session:start on qa-android-01', effect('usr_acme_viewer', A, 'session:start', 'dev_qa_android_01'), 'deny');

console.log('\n== §11 vector 4/5 — device-scoped deny (D1) ==');
check('viewer: device:view on kiosk-lobby-01', effect('usr_acme_viewer', A, 'device:view', 'dev_kiosk_lobby_01'), 'deny');
check('viewer: device:view reason=explicit_deny', reason('usr_acme_viewer', A, 'device:view', 'dev_kiosk_lobby_01'), 'explicit_deny');
check('viewer: device:view on lab-win-01', effect('usr_acme_viewer', A, 'device:view', 'dev_lab_win_01'), 'allow');

console.log('\n== §11 vector 7 — org-wide DENY beats the role baseline (D1) ==');
check('operator(sam): device:terminal on build-server-01', effect('usr_sam', A, 'device:terminal', 'dev_build_server_01'), 'deny');
check('operator(sam): device:terminal on lab-win-01', effect('usr_sam', A, 'device:terminal', 'dev_lab_win_01'), 'deny');
check('operator(sam): device:control still ALLOW', effect('usr_sam', A, 'device:control', 'dev_lab_win_01'), 'allow');

console.log('\n== the discriminating case: org-wide deny + device-scoped allow ==');
db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,created_by) VALUES (?,?,?,?,?,?)')
  .run('g_carve', A, 'usr_sam', 'dev_lab_win_01', 'allow', 'usr_acme_owner');
db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('g_carve', 'device:terminal');
check('device-scoped ALLOW does NOT carve out org-wide DENY', effect('usr_sam', A, 'device:terminal', 'dev_lab_win_01'), 'deny');

console.log('\n== §7 — multi-org: same user, different role per org ==');
check('dana: org:delete in Acme (owner)', effect('usr_dana', A, 'org:delete'), 'allow');
check('dana: org:delete in Globex (viewer)', effect('usr_dana', G, 'org:delete'), 'deny');
check('dana: device:control on globex-desk-01 (grant)', effect('usr_dana', G, 'device:control', 'dev_globex_desk_01'), 'allow');
check('dana: device:control on globex-kiosk-02', effect('usr_dana', G, 'device:control', 'dev_globex_kiosk_02'), 'deny');

console.log('\n== §6 — cross-org is invisible: no membership means total deny ==');
check('dana has no membership in org_nope', resolve(db, { userId: 'usr_dana', orgId: 'org_nope' }).role, null);
check('  ...every permission denied', effect('usr_dana', 'org_nope', 'device:list'), 'deny');
check('  ...reason=not_a_member', reason('usr_dana', 'org_nope', 'device:list'), 'not_a_member');

console.log('\n== D7 — half-open time window ==');
const past = new Date(Date.now() - 1000).toISOString();
const future = new Date(Date.now() + 3600_000).toISOString();
db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,expires_at,created_by) VALUES (?,?,?,?,?,?,?)')
  .run('g_expired', A, 'usr_acme_viewer', 'dev_lab_win_01', 'allow', past, 'usr_acme_owner');
db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('g_expired', 'device:control');
check('expired grant is inert', effect('usr_acme_viewer', A, 'device:control', 'dev_lab_win_01'), 'deny');

db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,created_by) VALUES (?,?,?,?,?,?,?)')
  .run('g_future', A, 'usr_acme_viewer', 'dev_lab_win_01', 'allow', future, 'usr_acme_owner');
db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('g_future', 'device:control');
check('not-yet-started grant is inert', effect('usr_acme_viewer', A, 'device:control', 'dev_lab_win_01'), 'deny');

console.log('\n== wildcards ==');
db.prepare('INSERT INTO grants (id,org_id,user_id,device_id,effect,created_by) VALUES (?,?,?,?,?,?)')
  .run('g_wild', A, 'usr_acme_viewer', 'dev_lab_win_01', 'allow', 'usr_acme_owner');
db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)').run('g_wild', 'device:*');
check('device:* allows device:control', effect('usr_acme_viewer', A, 'device:control', 'dev_lab_win_01'), 'allow');
check('device:* does NOT allow session:start', effect('usr_acme_viewer', A, 'session:start', 'dev_lab_win_01'), 'deny');
check('device:* does NOT allow audit:read', effect('usr_acme_viewer', A, 'audit:read'), 'deny');

console.log('\n== §9 — compound session check ==');
const ctx = { userId: 'usr_acme_viewer', orgId: A };
check('viewer: view session on lab-mac-01 (start+view)', (() => { try { assertCanStartSession(db, ctx, 'view', 'dev_lab_mac_01'); return 'ok'; } catch (e) { return e.reason; } })(), 'ok');
check('viewer: control session on lab-mac-01 -> missing_device_permission', (() => { try { assertCanStartSession(db, ctx, 'control', 'dev_lab_mac_01'); return 'ok'; } catch (e) { return e.reason; } })(), 'missing_device_permission');
check('viewer: view session on qa-android-01 -> missing_permission', (() => { try { assertCanStartSession(db, ctx, 'view', 'dev_qa_android_01'); return 'ok'; } catch (e) { return e.reason; } })(), 'missing_permission');

console.log('\n== §7 — suspended membership yields an empty permission set ==');
db.prepare("UPDATE memberships SET status='suspended', perm_version = perm_version + 1 WHERE org_id=? AND user_id=?").run(A, 'usr_acme_viewer');
check('suspended: device:list denied', effect('usr_acme_viewer', A, 'device:list'), 'deny');
check('suspended: reason=suspended', reason('usr_acme_viewer', A, 'device:list'), 'suspended');
check('suspended: device:view denied on every device', effect('usr_acme_viewer', A, 'device:view', 'dev_lab_mac_01'), 'deny');

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
