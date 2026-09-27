import {
  hashInviteToken, hashPassword, issueAccessToken, newInviteToken, verifyPassword,
} from '../auth.js';
import { audit, auditDenials } from '../audit.js';
import { bumpPermVersion, newId, nowIso } from '../db.js';
import { assertCan, assertCanStartSession, assertMayGrant, resolveDevices } from '../permissions.js';
import {
  assertCanModify, assertNotLastOwner, assertRoleExists, endActiveSessions,
  sessionExpiry, snapshotAuthority,
} from '../lifecycle.js';
import {
  badRequest, conflict, deviceBusy, forbidden, gone, normalizeTs, notFound, send,
  selfRoleChange, unauthenticated,
} from '../http.js';

function membership(db, userId, orgId) {
  return db.prepare('SELECT * FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId);
}

function issueForMembership(user, member, secret) {
  return issueAccessToken({ userId: user.id, orgId: member.org_id, role: member.role, permVersion: member.perm_version }, secret);
}

function insertAudit(db, ctx, action, targetType, targetId, result = 'allow', reasonCode = null) {
  audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action, targetType, targetId, result, reasonCode, requestId: ctx.requestId });
}

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  router.post('/v1/auth/login', (ctx, _params, res) => {
    const email = String(ctx.body.email ?? '').trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !verifyPassword(ctx.body.password, user.password_hash)) throw unauthenticated('invalid email or password');

    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role, m.perm_version, m.status
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL ORDER BY o.name`
    ).all(user.id);
    if (orgs.length === 0) throw unauthenticated();

    let selected = orgs[0];
    if (ctx.body.orgId) {
      selected = orgs.find((org) => org.id === ctx.body.orgId);
      if (!selected) throw notFound();
    }
    const token = issueAccessToken({ userId: user.id, orgId: selected.id, role: selected.role, permVersion: selected.perm_version }, secret);
    send(res, 200, { token, user: { id: user.id, email: user.email, name: user.name }, org: { id: selected.id, name: selected.name, theme: selected.theme }, orgs, role: selected.role });
  });

  router.post('/v1/auth/token', (ctx, _params, res) => {
    const selected = membership(db, ctx.userId, ctx.body.orgId);
    if (!selected || selected.status !== 'active') throw notFound();
    const org = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ? AND deleted_at IS NULL').get(selected.org_id);
    if (!org) throw notFound();
    send(res, 200, { token: issueForMembership(ctx.user, selected, secret), org, role: selected.role });
  });

  router.get('/v1/orgs/:orgId', (ctx, _params, res) => {
    assertCan(db, ctx, 'org:update');
    send(res, 200, { org: ctx.organization, role: ctx.role });
  });

  router.post('/v1/orgs', (ctx, _params, res) => {
    if (typeof ctx.body.name !== 'string' || !ctx.body.name.trim()) throw badRequest('name is required');
    const created = db.transaction(() => {
      const orgId = newId('org');
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(orgId, ctx.body.name.trim(), 'cobalt');
      db.prepare("INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'owner', 'active', ?)")
        .run(newId('mem'), orgId, ctx.userId, nowIso());
      insertAudit(db, ctx, 'org.create', 'org', orgId);
      return { id: orgId };
    })();
    send(res, 201, { ...created, role: 'owner' });
  });

  router.get('/v1/orgs/:orgId/devices', (ctx, _params, res) => {
    assertCan(db, ctx, 'device:list');
    const devices = db.prepare('SELECT id, org_id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name').all(ctx.orgId);
    const resolved = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: devices.map((device) => device.id) });
    const visible = [];
    for (const device of devices) {
      const permissions = resolved.byDevice[device.id];
      if (permissions['device:view']?.effect === 'allow') visible.push({ ...device, online: Boolean(device.online), permissions });
    }
    send(res, 200, { devices: visible });
  });

  router.get('/v1/orgs/:orgId/audit', (ctx, _params, res) => {
    assertCan(db, ctx, 'audit:read');
    const limit = Number(ctx.query.get('limit') ?? 50);
    const offset = Number(ctx.query.get('offset') ?? 0);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw badRequest('limit is out of range');
    if (!Number.isInteger(offset) || offset < 0) throw badRequest('offset is out of range');
    const events = db.prepare('SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?').all(ctx.orgId, limit, offset);
    send(res, 200, { events });
  });

  router.patch('/v1/orgs/:orgId/members/:userId', (ctx, { userId }, res) => {
    if (userId === ctx.userId) throw selfRoleChange();
    const target = membership(db, userId, ctx.orgId);
    if (!target) throw notFound();
    auditDenials(db, ctx, { action: 'member.role', targetType: 'member', targetId: userId }, () => assertCan(db, ctx, 'user:role:update'));
    assertRoleExists(db, ctx.body.role);
    assertCanModify(db, ctx.role, ctx.body.role);
    if (target.role === 'owner' && ctx.body.role !== 'owner') assertNotLastOwner(db, ctx.orgId, userId);
    db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(ctx.body.role, ctx.orgId, userId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId });
      insertAudit(db, ctx, 'member.role', 'member', userId);
    })();
    send(res, 200, { userId, role: ctx.body.role });
  });

  router.delete('/v1/orgs/:orgId/members/me', (ctx, _params, res) => {
    if (ctx.role === 'owner') assertNotLastOwner(db, ctx.orgId, ctx.userId);
    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?").run(ctx.orgId, ctx.userId);
      endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });
      insertAudit(db, ctx, 'member.leave', 'member', ctx.userId);
    })();
    send(res, 200, { removed: true });
  });

  router.post('/v1/orgs/:orgId/members/:userId/suspend', (ctx, { userId }, res) => {
    const target = membership(db, userId, ctx.orgId);
    if (!target) throw notFound();
    auditDenials(db, ctx, { action: 'member.suspend', targetType: 'member', targetId: userId }, () => assertCan(db, ctx, 'user:remove'));
    if (target.role === 'owner') assertNotLastOwner(db, ctx.orgId, userId);
    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?").run(ctx.orgId, userId);
      endActiveSessions(db, { orgId: ctx.orgId, userId, reason: 'user_suspended' });
      insertAudit(db, ctx, 'member.suspend', 'member', userId);
    })();
    send(res, 200, { userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:orgId/members/:userId/suspend', (ctx, { userId }, res) => {
    const target = membership(db, userId, ctx.orgId);
    if (!target) throw notFound();
    assertCan(db, ctx, 'user:remove');
    db.prepare("UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?").run(ctx.orgId, userId);
    insertAudit(db, ctx, 'member.reinstate', 'member', userId);
    send(res, 200, { userId, status: 'active' });
  });

  router.post('/v1/orgs/:orgId/grants', (ctx, _params, res) => {
    const target = membership(db, ctx.body.userId, ctx.orgId);
    if (!target || target.status !== 'active') throw notFound();
    if (ctx.body.userId === ctx.userId) throw forbidden('cannot grant permissions to yourself', 'self_grant');
    const patterns = ctx.body.permissions;
    if (ctx.body.effect !== 'allow' && ctx.body.effect !== 'deny') throw badRequest('invalid grant effect');
    auditDenials(db, ctx, { action: 'grant.create', targetType: 'member', targetId: ctx.body.userId }, () => assertCan(db, ctx, 'grant:create'));
    const knownPatterns = new Set(db.prepare('SELECT pattern FROM permission_patterns').all().map((row) => row.pattern));
    for (const pattern of patterns ?? []) {
      if (!knownPatterns.has(pattern)) throw badRequest('unknown permission', 'unknown_permission');
    }
    auditDenials(db, ctx, { action: 'grant.create', targetType: 'member', targetId: ctx.body.userId }, () => assertMayGrant(db, ctx, patterns, ctx.body.deviceId ?? null));
    const grantId = newId('grt');
    db.transaction(() => {
      db.prepare('INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(grantId, ctx.orgId, ctx.body.userId, ctx.body.deviceId ?? null, ctx.body.effect, normalizeTs(ctx.body.startsAt, 'startsAt'), normalizeTs(ctx.body.expiresAt, 'expiresAt'), ctx.userId);
      for (const pattern of patterns) db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)').run(grantId, pattern);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: ctx.body.userId });
      insertAudit(db, ctx, 'grant.create', 'grant', grantId);
    })();
    send(res, 201, { id: grantId });
  });

  router.delete('/v1/orgs/:orgId/grants/:grantId', (ctx, { grantId }, res) => {
    const grant = db.prepare('SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(grantId, ctx.orgId);
    if (!grant) throw notFound();
    assertCan(db, ctx, 'grant:revoke');
    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grantId);
      bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
      insertAudit(db, ctx, 'grant.revoke', 'grant', grantId);
    })();
    send(res, 200, { revoked: true });
  });

  router.post('/v1/orgs/:orgId/invites', (ctx, _params, res) => {
    auditDenials(db, ctx, { action: 'invite.create', targetType: 'invite', targetId: null }, () => assertCan(db, ctx, 'user:invite'));
    const email = String(ctx.body.email ?? '').trim().toLowerCase();
    if (!email.includes('@')) throw badRequest('valid email is required');
    assertRoleExists(db, ctx.body.role);
    assertCanModify(db, ctx.role, ctx.body.role);
    const rawToken = newInviteToken();
    const inviteId = newId('inv');
    const expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .run(inviteId, ctx.orgId, email, ctx.body.role, hashInviteToken(rawToken), ctx.userId, expiresAt);
        insertAudit(db, ctx, 'invite.create', 'invite', inviteId);
      })();
    } catch (error) {
      if (String(error.message).includes('one_live_invite_per_email')) throw conflict('an active invite already exists');
      throw error;
    }
    send(res, 201, { id: inviteId, inviteToken: rawToken, expiresAt });
  });

  router.get('/v1/invites/:token', (_ctx, { token }, res) => {
    const invite = db.prepare('SELECT i.expires_at, i.accepted_at, i.revoked_at, o.name AS org_name FROM invites i JOIN organizations o ON o.id = i.org_id WHERE i.token_hash = ?').get(hashInviteToken(token));
    if (!invite) throw notFound();
    if (invite.accepted_at || invite.revoked_at || invite.expires_at <= nowIso()) throw gone();
    send(res, 200, { orgName: invite.org_name, expiresAt: invite.expires_at });
  });

  router.post('/v1/invites/:token/accept', (ctx, { token }, res) => {
    const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(token));
    if (!invite) throw notFound();
    if (invite.accepted_at || invite.revoked_at) throw conflict('invite is no longer valid');
    if (invite.expires_at <= nowIso()) throw gone();
    const name = String(ctx.body.name ?? '').trim();
    const password = String(ctx.body.password ?? '');
    if (!name || password.length < 8) throw badRequest('name and a password of at least 8 characters are required');
    const result = db.transaction(() => {
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const userId = newId('usr');
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').run(userId, invite.email, name, hashPassword(password));
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      }
      let member = membership(db, user.id, invite.org_id);
      if (!member) {
        db.prepare("INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, 'active', ?)")
          .run(newId('mem'), invite.org_id, user.id, invite.role, nowIso());
        member = membership(db, user.id, invite.org_id);
      }
      db.prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?').run(nowIso(), user.id, invite.id);
      const org = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(invite.org_id);
      return { user, member, org };
    })();
    send(res, 200, { token: issueForMembership(result.user, result.member, secret), role: result.member.role, org: result.org });
  });

  router.get('/v1/orgs/:orgId/sessions', (ctx, _params, res) => {
    assertCan(db, ctx, 'session:view');
    const sessions = db.prepare('SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC').all(ctx.orgId);
    send(res, 200, { sessions });
  });

  router.post('/v1/orgs/:orgId/sessions', (ctx, _params, res) => {
    const device = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(ctx.body.deviceId, ctx.orgId);
    if (!device) throw notFound();
    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: device.id }, () => assertCanStartSession(db, ctx, ctx.body.mode, device.id));
    if (ctx.body.mode !== 'view') {
      const existing = db.prepare("SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')").get(device.id);
      if (existing) throw deviceBusy();
    }
    const sessionId = newId('ses');
    const expiry = sessionExpiry(db, ctx.orgId);
    const authority = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .run(sessionId, ctx.orgId, ctx.userId, device.id, ctx.body.mode, 'active', JSON.stringify(authority), expiry);
        insertAudit(db, ctx, 'session.start', 'device', device.id);
      })();
    } catch (error) {
      if (String(error.message).includes('one_exclusive_session_per_device')) throw deviceBusy();
      throw error;
    }
    send(res, 201, db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId));
  });

  router.get('/v1/sessions/:sessionId', (ctx, { sessionId }, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?').get(sessionId, ctx.orgId);
    if (!session) throw notFound();
    assertCan(db, ctx, 'session:view');
    send(res, 200, session);
  });

  router.post('/v1/orgs/:orgId/sessions/:sessionId/stop', (ctx, { sessionId }, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND org_id = ?').get(sessionId, ctx.orgId);
    if (!session) throw notFound();
    if (session.user_id !== ctx.userId) assertCan(db, ctx, 'session:terminate');
    db.prepare("UPDATE sessions SET state = 'ended', end_reason = 'user_stopped', ended_at = ? WHERE id = ? AND state = 'active'").run(nowIso(), sessionId);
    insertAudit(db, ctx, 'session.stop', 'session', sessionId);
    send(res, 200, { stopped: true });
  });
}
