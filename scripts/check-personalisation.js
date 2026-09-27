// The personalisation floor. Exercises YOUR engine against an organization that did
// not exist when the specs were written. Run: node scripts/check-personalisation.js
//
// This is the floor, not the grade. It proves your engine reads roles, permissions and
// grants from the DATABASE rather than from the documented matrix. Grading runs the same
// shape of check with a DIFFERENT nonce, so passing this by special-casing the values
// printed below will not help.
//
// It builds a throwaway in-memory database (schema + reference + overlay), exactly like
// scripts/check-permissions.js does — your app.db is not touched.

import { readFileSync } from 'node:fs';
import { openDatabase } from '../server/db.js';
import { resolve } from '../server/permissions.js';
import { readNonce, buildOverlay, applyOverlay, expectations, DOCUMENTED_PERMISSIONS } from './personalise.js';

const overlay = buildOverlay(readNonce());

if (!overlay) {
  console.log('\nNo .candidate-nonce file and no CANDIDATE_NONCE set.');
  console.log('Nothing to check: the database holds the documented fixture only.');
  console.log('Set a nonce to exercise the personalised organization.\n');
  process.exit(0);
}

const db = openDatabase(':memory:');
db.exec(readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8'));
db.exec(readFileSync(new URL('../db/reference.sql', import.meta.url), 'utf8'));
applyOverlay(db, overlay, { passwordHash: () => 'x' });

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

const e = expectations(overlay);
const ctx = { userId: e.userId, orgId: e.orgId };

console.log(`\n== personalisation ${overlay.fingerprint} ==`);
console.log(`   role ${e.role} · permission ${e.permission} · org ${overlay.org.name}\n`);

let catalogue, onAllow, onDeny, orgWide;
try {
  onAllow = resolve(db, { ...ctx, deviceId: e.allowOn });
  onDeny  = resolve(db, { ...ctx, deviceId: e.denyOn });
  orgWide = resolve(db, ctx);
  catalogue = Object.keys(onAllow.permissions);
} catch (err) {
  console.log(`  FAIL  could not resolve at all: ${err.message}`);
  console.log('\n  server/permissions.js is still a stub. Implement it, then re-run.\n');
  process.exit(1);
}

console.log('== the database, not the docs, is the catalogue ==');
const dbCatalogue = db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);
check('resolved set covers every permission in the table', catalogue.slice().sort(), dbCatalogue);
check('...including the undocumented one', catalogue.includes(e.permission), true);
check('...and the documented 19 are all still there', DOCUMENTED_PERMISSIONS.every((p) => catalogue.includes(p)), true);

console.log('\n== the undocumented role resolves ==');
check('role comes from the membership row', onAllow.role, e.role);
check('baseline is allow on the first device', e.baseline.every((p) => onAllow.permissions[p].effect === 'allow'), true);
check('baseline is allow on the second device too', e.baseline.every((p) => onDeny.permissions[p].effect === 'allow'), true);

console.log('\n== allow / explicit_deny / implicit are three different answers ==');
check(`${e.permission} on ${e.allowOn}`, onAllow.permissions[e.permission].effect, 'allow');
check('  ...source is the grant', onAllow.permissions[e.permission].source, e.allowSource);
check(`${e.permission} on ${e.denyOn}`, onDeny.permissions[e.permission].effect, 'deny');
check('  ...reason is explicit_deny', onDeny.permissions[e.permission].reason, 'explicit_deny');
check('  ...source is the denying grant', onDeny.permissions[e.permission].source, e.denySource);
check('a device-scoped deny is not carved out', onDeny.permissions[e.permission].effect, 'deny');

console.log('\n== an unrelated permission denies implicitly ==');
const never = catalogue.find((p) => !e.baseline.includes(p) && p !== e.permission);
check(`${never} reason`, onAllow.permissions[never].reason, 'implicit');
check(`${never} has no source`, onAllow.permissions[never].source, null);

console.log('\n== the documented viewer baseline still holds in a new org ==');
const bystander = resolve(db, { userId: e.bystanderId, orgId: e.orgId, deviceId: e.allowOn });
const viewerAllows = Object.keys(bystander.permissions).filter((p) => bystander.permissions[p].effect === 'allow').sort();
check('role', bystander.role, 'viewer');
check('viewer allows are exactly the documented four', viewerAllows, ['device:list', 'device:view', 'session:view', 'user:read']);
check('viewer does not get the new permission', bystander.permissions[e.permission].effect, 'deny');
check('  ...and the reason is implicit, not suspended or denied', bystander.permissions[e.permission].reason, 'implicit');

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed`);
console.log('Grading uses a different nonce. Read the tables at runtime; never hardcode.\n');
process.exit(fail === 0 ? 0 : 1);
