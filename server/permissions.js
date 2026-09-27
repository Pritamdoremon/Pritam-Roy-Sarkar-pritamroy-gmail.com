// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { badRequest, forbidden, notFound, unauthenticated } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

function matchesPattern(pattern, permission) {
  if (pattern === '*') return true;
  if (pattern === permission.key) return true;
  return pattern === `${permission.resource}:*`;
}

function loadPermissionData(db, { userId, orgId, now }) {
  const permissions = db.prepare('SELECT key, resource FROM permissions ORDER BY key').all();
  const membership = db.prepare(
    `SELECT m.role, m.status
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ? AND o.deleted_at IS NULL`
  ).get(userId, orgId);

  const data = {
    permissions,
    membership,
    rolePermissions: new Set(),
    grants: [],
    deviceIds: [],
    deviceIdSet: new Set(),
  };

  if (!membership || membership.status !== 'active') return data;

  const nowIso = new Date(now).toISOString();
  data.rolePermissions = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(membership.role)
      .map((row) => row.permission)
  );
  data.grants = db.prepare(
    `SELECT g.id, g.device_id, g.effect, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
      ORDER BY g.id`
  ).all(userId, orgId, nowIso, nowIso);
  data.deviceIds = db.prepare(
    'SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY id'
  ).all(orgId).map((row) => row.id);
  data.deviceIdSet = new Set(data.deviceIds);

  return data;
}

function resolveAtDevice(data, deviceId) {
  const membership = data.membership;
  let deniedReason = 'not_a_member';

  if (membership?.status === 'suspended') deniedReason = 'suspended';
  if (!membership || membership.status !== 'active') {
    const denied = {};
    for (const permission of data.permissions) {
      denied[permission.key] = { effect: 'deny', source: null, reason: deniedReason };
    }
    return denied;
  }

  if (deviceId !== null && !data.deviceIdSet.has(deviceId)) {
    const denied = {};
    for (const permission of data.permissions) {
      denied[permission.key] = { effect: 'deny', source: null, reason: 'scope_mismatch' };
    }
    return denied;
  }

  const resolved = {};
  for (const permission of data.permissions) {
    let allowedGrant = null;
    let deniedGrant = null;

    for (const grant of data.grants) {
      const appliesToDevice = grant.device_id === null || grant.device_id === deviceId;
      if (!appliesToDevice || !matchesPattern(grant.pattern, permission)) continue;

      if (grant.effect === 'deny') {
        deniedGrant = grant;
        break;
      }
      if (!allowedGrant) allowedGrant = grant;
    }

    if (deniedGrant) {
      resolved[permission.key] = {
        effect: 'deny',
        source: `grant:${deniedGrant.id}`,
        reason: 'explicit_deny',
      };
    } else if (data.rolePermissions.has(permission.key)) {
      resolved[permission.key] = {
        effect: 'allow',
        source: `role:${membership.role}`,
        reason: null,
      };
    } else if (allowedGrant) {
      resolved[permission.key] = {
        effect: 'allow',
        source: `grant:${allowedGrant.id}`,
        reason: null,
      };
    } else {
      resolved[permission.key] = { effect: 'deny', source: null, reason: 'implicit' };
    }
  }

  return resolved;
}

function resolveOrgPermissions(data) {
  if (!data.membership || data.membership.status !== 'active') {
    return resolveAtDevice(data, null);
  }

  const devicePermissionSets = [];
  if (data.deviceIds.length === 0) {
    devicePermissionSets.push(resolveAtDevice(data, null));
  } else {
    for (const deviceId of data.deviceIds) {
      devicePermissionSets.push(resolveAtDevice(data, deviceId));
    }
  }

  const resolved = {};
  for (const permission of data.permissions) {
    let allowed = null;
    let explicitlyDenied = null;

    for (const devicePermissions of devicePermissionSets) {
      const result = devicePermissions[permission.key];
      if (result.effect === 'allow') {
        allowed = result;
        break;
      }
      if (result.reason === 'explicit_deny' && !explicitlyDenied) {
        explicitlyDenied = result;
      }
    }

    if (allowed) {
      resolved[permission.key] = allowed;
    } else if (explicitlyDenied) {
      resolved[permission.key] = explicitlyDenied;
    } else {
      resolved[permission.key] = { effect: 'deny', source: null, reason: 'implicit' };
    }
  }

  return resolved;
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const data = loadPermissionData(db, { userId, orgId, now });
  const permissions = deviceId === null
    ? resolveOrgPermissions(data)
    : resolveAtDevice(data, deviceId);

  return { role: data.membership?.role ?? null, permissions };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const data = loadPermissionData(db, { userId, orgId, now });
  const byDevice = {};

  for (const deviceId of deviceIds) {
    byDevice[deviceId] = resolveAtDevice(data, deviceId);
  }

  return { role: data.membership?.role ?? null, byDevice };
}

export function can(db, ctx, permission, deviceId) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  }).permissions[permission];

  return result?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const result = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  }).permissions[permission];

  if (result?.effect === 'allow') return;
  if (result?.reason === 'scope_mismatch') throw notFound();
  if (result?.reason === 'not_a_member') throw unauthenticated();

  const reason = result?.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission';
  throw forbidden('missing permission', reason);
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw badRequest('at least one permission is required');
  }

  const data = loadPermissionData(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    now: new Date(),
  });
  const knownPatterns = new Set(
    db.prepare('SELECT pattern FROM permission_patterns').all().map((row) => row.pattern)
  );
  const requestedPermissions = new Set();

  for (const pattern of patterns) {
    if (!knownPatterns.has(pattern)) throw badRequest('unknown permission pattern');

    let matched = false;
    for (const permission of data.permissions) {
      if (matchesPattern(pattern, permission)) {
        requestedPermissions.add(permission.key);
        matched = true;
      }
    }
    if (!matched) throw badRequest('permission pattern matches nothing');
  }

  const currentPermissions = resolveAtDevice(data, deviceId);
  for (const permission of requestedPermissions) {
    const result = currentPermissions[permission];
    if (result.effect === 'allow') continue;
    if (result.reason === 'scope_mismatch') throw notFound();
    if (result.reason === 'not_a_member') throw unauthenticated();
    const reason = result.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission';
    throw forbidden('cannot grant a permission you do not hold', reason);
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest('invalid session mode');

  const data = loadPermissionData(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    now: new Date(),
  });
  const permissions = resolveAtDevice(data, deviceId);
  const startPermission = permissions['session:start'];

  if (startPermission?.effect !== 'allow') {
    if (startPermission?.reason === 'scope_mismatch') throw notFound();
    if (startPermission?.reason === 'not_a_member') throw unauthenticated();
    const reason = startPermission?.reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission';
    throw forbidden('missing session:start permission', reason);
  }

  if (permissions[modePermission]?.effect !== 'allow') {
    throw forbidden('missing device permission', 'missing_device_permission');
  }
}
