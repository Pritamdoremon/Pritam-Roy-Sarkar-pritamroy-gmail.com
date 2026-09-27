// Per-candidate fixture overlay.
//
// WHY THIS EXISTS
//
// The published fixture (seed/orgs.json) and the prose specs together describe the
// whole model: 5 roles, 19 permissions, one role->permission matrix, one device-scoped
// grant. That is enough to hardcode a passing implementation without ever reading the
// database — which is the failure mode this file removes.
//
// This module adds ONE extra organization to the candidate's database, containing:
//   - a role that appears in no document
//   - a permission that appears in no document
//   - a per-candidate baseline for that role
//   - a device-scoped allow and a device-scoped deny of that permission, on two
//     different devices of the same org, so the three distinguishable outcomes
//     (allow / explicit_deny / implicit) are all reachable
//   - a plain `viewer` in the same org, to prove the documented baselines still hold
//
// The overlay is ADDITIVE AND DETERMINISTIC. It never touches the two documented
// organizations, their users, devices, grants or memberships, so every shipped public
// suite stays calibrated and keeps passing. That constraint is not a nicety: the suites
// assert exact counts (check-api.js:54, :92; ui.spec.js:129, :192, :234), and a
// non-additive overlay would make every candidate look broken.
//
// WHAT THE HIDDEN TIER DOES WITH IT
//
// The nonce is a file (.candidate-nonce), optionally overridden by CANDIDATE_NONCE.
// The committed nonce is one instance. Grading runs with a DIFFERENT one, so hardcoding
// the values you can read here fails just as hard as hardcoding the documented matrix.
// The contract to rely on is the API below, not any particular draw.
//
// NO DEPENDENCIES. Deterministic. Run standalone:  node scripts/personalise.js

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const THEMES = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];

// The 19 documented permissions. Used ONLY to draw a plausible baseline subset — never
// to decide allow/deny, and never as an exhaustive truth. If a permission is ever added
// to db/reference.sql without being listed here, the overlay is unaffected.
export const DOCUMENTED_PERMISSIONS = [
  'device:list', 'device:view', 'device:control', 'device:terminal',
  'device:file_transfer', 'device:provision', 'device:update',
  'session:start', 'session:view', 'session:terminate',
  'grant:create', 'grant:revoke',
  'user:read', 'user:invite', 'user:role:update', 'user:remove',
  'audit:read',
  'org:update', 'org:delete',
];

// Drawn per nonce. Every one collides with nothing in db/reference.sql, which is what
// makes a hardcoded catalogue, wildcard expansion, or rank table fail loudly.
const ROLE_POOL = ['analyst', 'duty_manager', 'field_tech', 'reviewer', 'intake_lead'];
const RANK_POOL = [5, 15, 25, 35, 45]; // 10/20/30/40/50 are taken; rank is UNIQUE
const PERMISSION_POOL = [
  'device:reboot', 'device:unlock', 'device:audit_log',
  'session:record', 'session:replay',
];
const ADJECTIVES = ['Quiet', 'Northwind', 'Bright', 'Ironside', 'Harbour', 'Vantage', 'Cinder', 'Lumen'];
const NOUNS = ['Harbor', 'Foundry', 'Signal', 'Works', 'Yard', 'Depot', 'Labs', 'Bridge'];
const LOCAL_PARTS = ['alex', 'jules', 'robin', 'kim', 'morgan', 'devon', 'ashe', 'noor'];
const DEVICE_KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

// --- determinism ------------------------------------------------------------

export function fingerprint(nonce) {
  return createHash('sha256').update(String(nonce)).digest('hex').slice(0, 12);
}

// mulberry32, seeded from the nonce digest. Small, fast, reproducible across platforms.
function rngFrom(hex) {
  let s = parseInt(hex.slice(0, 8), 16) >>> 0;
  return function next() {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];
const pickSome = (rng, arr, n) => {
  const pool = [...arr];
  const out = [];
  while (out.length < n && pool.length) out.push(...pool.splice(Math.floor(rng() * pool.length), 1));
  return out;
};

// --- the overlay ------------------------------------------------------------

/**
 * Build the deterministic overlay for a nonce. Returns null when there is no nonce, so
 * `npm run db:reset` without a nonce still produces exactly the documented fixture.
 */
export function buildOverlay(nonce) {
  if (nonce === null || nonce === undefined || String(nonce).trim() === '') return null;

  const digest = String(nonce).trim();
  const hex = createHash('sha256').update(digest).digest('hex');
  const rng = rngFrom(hex);
  const slug = hex.slice(0, 6);

  // Draw order is fixed. Changing it changes every candidate's fixture, so don't.
  const roleKey = pick(rng, ROLE_POOL);
  const roleRank = pick(rng, RANK_POOL);
  const permissionKey = pick(rng, PERMISSION_POOL);
  const orgName = `${pick(rng, ADJECTIVES)} ${pick(rng, NOUNS)}`;
  const theme = pick(rng, THEMES);
  const local = pick(rng, LOCAL_PARTS);
  const viewerLocal = pick(rng, LOCAL_PARTS);
  const [kindA, kindB] = pickSome(rng, DEVICE_KINDS, 2);
  const extraBaseline = pickSome(
    rng,
    DOCUMENTED_PERMISSIONS.filter((p) => !['device:list', 'device:view'].includes(p)),
    2
  );

  // device:list + device:view are ALWAYS in the baseline: without them the console
  // cannot render a device row at all, and the hidden UI tier would have nothing to
  // assert against. Everything else here varies per candidate.
  const baseline = ['device:list', 'device:view', ...extraBaseline].sort();

  const orgId = `org_p_${slug}`;
  const user = {
    id: `usr_p_${slug}`,
    email: `${local}.${slug}@example.test`,
    name: `${local[0].toUpperCase()}${local.slice(1)} ${roleKey.split('_').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ')}`,
  };
  // A plain documented role in the same org. Proves the documented baselines still
  // resolve in an organization that did not exist when the docs were written.
  const bystander = {
    id: `usr_p_${slug}_v`,
    email: `${viewerLocal}.${slug}.viewer@example.test`,
    name: `Bystander Viewer ${slug.slice(0, 4)}`,
  };

  const devices = [
    { id: `dev_p_${slug}_a`, name: `${roleKey}-primary`, kind: kindA, online: true },
    { id: `dev_p_${slug}_b`, name: `${roleKey}-secondary`, kind: kindB, online: false },
  ];

  const grants = [
    {
      id: `grt_p_${slug}_allow`,
      userId: user.id,
      deviceId: devices[0].id,
      effect: 'allow',
      permissions: [permissionKey],
    },
    {
      id: `grt_p_${slug}_deny`,
      userId: user.id,
      deviceId: devices[1].id,
      effect: 'deny',
      permissions: [permissionKey],
    },
  ];

  return {
    nonce: digest,
    fingerprint: fingerprint(digest),
    slug,
    role: { key: roleKey, rank: roleRank, label: roleKey.replace(/_/g, ' '), baseline },
    permission: { key: permissionKey, resource: permissionKey.split(':')[0], action: permissionKey.split(':')[1] },
    org: { id: orgId, name: orgName, theme, maxSessionMinutes: 60 },
    user,
    bystander,
    devices,
    grants,
    session: {
      id: `ses_p_${slug}`,
      userId: user.id,
      deviceId: devices[0].id,
      mode: 'view',
      state: 'ended',
      endReason: 'user_stopped',
    },
    audit: [
      { id: `aud_p_${slug}_a`, actorId: user.id, action: 'session.start', result: 'allow', reasonCode: null },
      { id: `aud_p_${slug}_d`, actorId: user.id, action: 'session.start', result: 'deny', reasonCode: 'missing_permission' },
    ],
  };
}

/**
 * The outcomes an engine must produce for this overlay, derived from the overlay itself
 * so no expected value is ever hardcoded — not here, and not in the grading tier.
 */
export function expectations(overlay) {
  const allow = overlay.grants.find((g) => g.effect === 'allow');
  const deny = overlay.grants.find((g) => g.effect === 'deny');
  return {
    role: overlay.role.key,
    permission: overlay.permission.key,
    baseline: overlay.role.baseline,
    allowOn: allow.deviceId,
    denyOn: deny.deviceId,
    allowSource: `grant:${allow.id}`,
    denySource: `grant:${deny.id}`,
    orgId: overlay.org.id,
    userId: overlay.user.id,
    bystanderId: overlay.bystander.id,
  };
}

/** The nonce: CANDIDATE_NONCE if set, else .candidate-nonce next to the repo root. */
export function readNonce() {
  const env = process.env.CANDIDATE_NONCE;
  if (env && String(env).trim()) return String(env).trim();
  try {
    const raw = readFileSync(new URL('../.candidate-nonce', import.meta.url), 'utf8').trim();
    return raw || null;
  } catch {
    return null;
  }
}

// --- writing it to a database ----------------------------------------------

/**
 * Persist the overlay. Additive: every id it writes is derived from the nonce, so it
 * cannot collide with the documented fixture, and nothing existing is read or updated.
 *
 * Requires schema.sql + reference.sql to be loaded already (FKs on roles, permissions,
 * permission_patterns, devices).
 */
export function applyOverlay(db, overlay, { passwordHash, now = new Date() } = {}) {
  if (!overlay) return false;
  const at = now.toISOString();
  const { role, permission, org, user, bystander, devices, grants, session, audit } = overlay;

  const write = db.transaction(() => {
    // 1. the undocumented role and permission, plus the pattern row that keeps the
    //    grant_permissions foreign key meaningful for this permission too.
    db.prepare('INSERT INTO roles (key, rank, label) VALUES (?,?,?)').run(role.key, role.rank, role.label);
    db.prepare('INSERT INTO permissions (key, resource, action, description) VALUES (?,?,?,?)')
      .run(permission.key, permission.resource, permission.action, `personalised: ${permission.key}`);
    db.prepare('INSERT INTO permission_patterns (pattern) VALUES (?)').run(permission.key);

    const rp = db.prepare('INSERT INTO role_permissions (role, permission) VALUES (?,?)');
    for (const p of role.baseline) rp.run(role.key, p);

    // 2. the org
    db.prepare('INSERT INTO organizations (id,name,theme,max_session_minutes) VALUES (?,?,?,?)')
      .run(org.id, org.name, org.theme, org.maxSessionMinutes);

    // 3. two users who exist in NO other org. Documented users are deliberately not
    //    touched: login() without an explicit orgId picks the caller's alphabetically
    //    first org, so adding a membership to a documented user would silently
    //    re-scope the shipped API tests.
    const u = db.prepare('INSERT INTO users (id,email,name,password_hash) VALUES (?,?,?,?)');
    u.run(user.id, user.email.toLowerCase(), user.name, passwordHash('demo1234'));
    u.run(bystander.id, bystander.email.toLowerCase(), bystander.name, passwordHash('demo1234'));

    const m = db.prepare('INSERT INTO memberships (id,org_id,user_id,role,status,joined_at) VALUES (?,?,?,?,?,?)');
    m.run(`mem_p_${overlay.slug}_a`, org.id, user.id, role.key, 'active', at);
    m.run(`mem_p_${overlay.slug}_v`, org.id, bystander.id, 'viewer', 'active', at);

    // 4. two devices in that org
    const d = db.prepare('INSERT INTO devices (id,org_id,name,kind,online) VALUES (?,?,?,?,?)');
    for (const dev of devices) d.run(dev.id, org.id, dev.name, dev.kind, dev.online ? 1 : 0);

    // 5. the allow and the deny, each scoped to a different device of the same org
    const g = db.prepare(
      'INSERT INTO grants (id,org_id,user_id,device_id,effect,starts_at,expires_at,created_by) VALUES (?,?,?,?,?,?,?,?)'
    );
    const gp = db.prepare('INSERT INTO grant_permissions (grant_id,permission) VALUES (?,?)');
    for (const grant of grants) {
      g.run(grant.id, org.id, grant.userId, grant.deviceId, grant.effect, null, null, user.id);
      for (const p of grant.permissions) gp.run(grant.id, p);
    }

    // 6. one ended session and two audit rows, so the Sessions and Audit surfaces are
    //    non-empty in the new org too
    db.prepare(
      `INSERT INTO sessions (id,org_id,user_id,device_id,mode,state,end_reason,authorized_by,started_at,expires_at,ended_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).run(session.id, org.id, session.userId, session.deviceId, session.mode, session.state,
          session.endReason, JSON.stringify({ role: role.key, grantIds: grants.map((x) => x.id), snapshotAt: at }),
          at, at, at);

    const a = db.prepare(
      `INSERT INTO audit_events (id,org_id,actor_id,action,target_type,target_id,result,reason_code,request_id,at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    );
    for (const e of audit) a.run(e.id, org.id, e.actorId, e.action, 'device', devices[0].id, e.result, e.reasonCode, null, at);
  });

  write();
  return true;
}

/** Human-readable summary, printed by the loader so the fixture is never a surprise. */
export function describeOverlay(overlay) {
  if (!overlay) return '  personalisation: none (documented fixture only)';
  const lines = [
    '',
    `  personalisation fingerprint ${overlay.fingerprint}`,
    `    extra role        ${overlay.role.key} (rank ${overlay.role.rank})`,
    `    extra permission  ${overlay.permission.key}   <- NOT in db/reference.sql or the docs`,
    `    extra org         ${overlay.org.name} (${overlay.org.id})`,
    `    baseline          ${overlay.role.baseline.join(', ')}`,
    `    ${overlay.permission.key}  allow on ${overlay.grants[0].deviceId}, deny on ${overlay.grants[1].deviceId}`,
    '',
    `    login  ${overlay.user.email} / demo1234   (role: ${overlay.role.key})`,
    `    login  ${overlay.bystander.email} / demo1234   (role: viewer)`,
    '',
    '    Read roles and permissions from the database. Do not encode the documented matrix.',
  ];
  return lines.join('\n');
}

// --- standalone: node scripts/personalise.js --------------------------------

const invokedDirectly = process.argv[1] && /personalise\.js$/.test(process.argv[1]);
if (invokedDirectly) {
  const overlay = buildOverlay(readNonce());
  if (!overlay) {
    console.log('No nonce found. Either set CANDIDATE_NONCE, or write .candidate-nonce.');
    console.log('The database will contain the documented fixture only.');
  } else {
    console.log(JSON.stringify(overlay, null, 2));
    console.log(describeOverlay(overlay));
  }
}
