// Per-request context: turn a bearer token into an authenticated caller.
//
// YOURS TO WRITE. This file ships as a stub so the server boots and every
// authenticated request fails loudly instead of appearing to work.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6):
//   - read the bearer token, verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that
//     names a different org is INVISIBLE — 404, never 403. Isolation is structural:
//     the caller cannot name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version (AUTH-DATA-MODEL.md §3), so a
//     role or grant change takes effect on the NEXT request, not at token expiry
//   - throw through the one error path in ./http.js
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries at
// least { userId, orgId, role, membership, claims }.

import { assertFresh, verifyAccessToken } from './auth.js';
import { notFound, unauthenticated } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const authorization = req.headers.authorization ?? '';
    const bearer = /^Bearer\s+(.+)$/i.exec(authorization);
    if (!bearer) throw unauthenticated();

    const claims = verifyAccessToken(bearer[1], secret);
    if (typeof claims.sub !== 'string' || typeof claims.org !== 'string') {
      throw unauthenticated();
    }

    const requestedOrgId = params?.orgId ?? params?.org;
    if (requestedOrgId && requestedOrgId !== claims.org) throw notFound();

    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(claims.sub);
    if (!user) throw unauthenticated();

    const organization = db.prepare(
      'SELECT id, name, theme FROM organizations WHERE id = ?'
    ).get(claims.org);
    if (!organization) throw unauthenticated();

    const membership = db.prepare(
      'SELECT * FROM memberships WHERE user_id = ? AND org_id = ?'
    ).get(user.id, organization.id);
    if (!membership || membership.status !== 'active') throw unauthenticated();

    assertFresh(claims, membership);

    return {
      userId: user.id,
      orgId: organization.id,
      role: membership.role,
      user,
      organization,
      membership,
      claims,
    };
  };
}
