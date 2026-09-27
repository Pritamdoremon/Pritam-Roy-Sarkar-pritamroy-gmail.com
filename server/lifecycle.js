// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { badRequest, forbidden, lastOwner } from './http.js';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((row) => [row.key, row.rank]));
}

export function assertRoleExists(db, role) {
  const found = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!found) throw badRequest('unknown role', 'unknown_role');
}

export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  if (ranks[callerRole] === undefined || ranks[targetRole] === undefined || ranks[callerRole] <= ranks[targetRole]) {
    throw forbidden('cannot modify this role', 'role_hierarchy');
  }
}

export function assertNotLastOwner(db, orgId, userId) {
  const owners = db.prepare(
    "SELECT count(*) AS count FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active' AND user_id <> ?"
  ).get(orgId, userId).count;
  if (owners === 0) throw lastOwner();
}

export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  let sql = "UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE org_id = ? AND state = 'active'";
  const values = [reason, orgId];
  if (userId) { sql += ' AND user_id = ?'; values.push(userId); }
  if (deviceId) { sql += ' AND device_id = ?'; values.push(deviceId); }
  if (exceptSessionId) { sql += ' AND id <> ?'; values.push(exceptSessionId); }
  return db.prepare(sql).run(...values).changes;
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const member = db.prepare('SELECT role FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId);
  const grantIds = db.prepare(
    `SELECT DISTINCT g.id FROM grants g JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR g.device_id = ?)`
  ).all(userId, orgId, deviceId).map((row) => row.id);
  return { role: member?.role ?? null, grantIds, snapshotAt: new Date().toISOString() };
}

export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  return new Date(Date.now() + (org?.max_session_minutes ?? 60) * 60000).toISOString();
}
