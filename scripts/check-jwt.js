// Exercises `verifyAccessToken` against AUTH-DATA-MODEL.md §10 and §2.
// Run: node scripts/check-jwt.js
//
// Why the rejection cases are written the way they are: a test that only asserts
// "this token is rejected" passes for a stub that throws unconditionally, and for a
// function that throws the wrong error. So every negative case asserts the *shape* of
// the rejection — a 401 UNAUTHENTICATED, nothing else. An unimplemented stub therefore
// fails all of these rather than passing them by accident.

import { createHmac, randomBytes } from 'node:crypto';
import { verifyAccessToken, signToken } from '../server/auth.js';
import { HttpError } from '../server/http.js';

const SECRET = 'test-secret';
const WRONG_SECRET = 'not-the-secret';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

const b64 = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
const nowSec = () => Math.floor(Date.now() / 1000);
const hmac = (data, secret = SECRET) => createHmac('sha256', secret).update(data).digest();

// The claim set from AUTH-DATA-MODEL.md §2. Override anything by passing it in.
const claims = (over = {}) => ({
  iss: ISS, aud: AUD, sub: 'usr_acme_viewer', org: 'org_acme', role: 'viewer',
  pv: 1, jti: 'jti-0001', iat: nowSec(), exp: nowSec() + 900, ...over,
});

// The attacker's toolkit: forge a token with an arbitrary header, payload and signature.
const forge = (header, payload, sig = (h, p) => hmac(`${h}.${p}`)) => {
  const h = b64(header), p = b64(payload);
  return `${h}.${p}.${sig(h, p).toString('base64url')}`;
};

const HS256 = { alg: 'HS256', typ: 'JWT' };

// --- tiny assertion harness (same shape as check-permissions.js) -------------
let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(58)} ${ok ? '' : `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

// Collapse an outcome to one comparable string. Anything that is not a 401
// UNAUTHENTICATED is reported verbatim, so a wrong error type is visible in the output.
const outcome = (token, secret = SECRET) => {
  try {
    verifyAccessToken(token, secret);
    return 'accepted';
  } catch (e) {
    return e instanceof HttpError ? `${e.status} ${e.code}` : `${e?.constructor?.name ?? 'throw'}: ${e?.message}`;
  }
};

// Read a claim without letting an unimplemented stub crash the run.
const claimOf = (token, key) => {
  try { return verifyAccessToken(token, SECRET)?.[key] ?? null; } catch { return 'threw'; }
};

const WANT = '401 UNAUTHENTICATED';

// ---------------------------------------------------------------------------
console.log('\n== §2 — a well-formed token round-trips ==');
const good = signToken(claims(), SECRET);
const [h, p, s] = good.split('.');

check('valid token is accepted', outcome(good), 'accepted');
check('  ...sub preserved', claimOf(good, 'sub'), 'usr_acme_viewer');
check('  ...org preserved', claimOf(good, 'org'), 'org_acme');
check('  ...role preserved', claimOf(good, 'role'), 'viewer');
check('  ...pv preserved', claimOf(good, 'pv'), 1);
check('  ...jti preserved', claimOf(good, 'jti'), 'jti-0001');

if (outcome(good) !== 'accepted') {
  console.log('\n  NOTE: verifyAccessToken is not implemented yet, or rejects a valid token.');
  console.log('        Every rejection case below fails as a result. That is the suite working');
  console.log('        as intended — it will not hand out free marks for a stub.\n');
}

// ---------------------------------------------------------------------------
console.log('\n== §10 — malformed input ==');
check('null token', outcome(null), WANT);
check('undefined token', outcome(undefined), WANT);
check('empty string', outcome(''), WANT);
check('one segment', outcome('just-a-string'), WANT);
check('two segments', outcome('aaa.bbb'), WANT);
check('four segments', outcome(`${h}.${p}.${s}.extra`), WANT);
check('header is not JSON', outcome(`${b64('not json')}.${p}.${s}`), WANT);
check('payload is not JSON', outcome(forge(HS256, 'not json')), WANT);
check('header is not an object', outcome(forge('HS256', claims())), WANT);

// ---------------------------------------------------------------------------
console.log('\n== §10 — algorithm confusion (do not trust the header) ==');
check('alg: none, empty signature', outcome(forge({ alg: 'none', typ: 'JWT' }, claims(), () => Buffer.alloc(0))), WANT);
check('alg: none, bare trailing dot', outcome(`${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims())}.`), WANT);
check('alg: none, original signature kept', outcome(`${b64({ alg: 'none', typ: 'JWT' })}.${p}.${s}`), WANT);
check('alg: HS512 substitution', outcome(forge({ alg: 'HS512', typ: 'JWT' }, claims())), WANT);
check('alg: RS256 substitution', outcome(forge({ alg: 'RS256', typ: 'JWT' }, claims())), WANT);
check('alg missing', outcome(forge({ typ: 'JWT' }, claims())), WANT);
check('typ missing', outcome(forge({ alg: 'HS256' }, claims())), WANT);
check('typ wrong', outcome(forge({ alg: 'HS256', typ: 'JWT2' }, claims())), WANT);

// ---------------------------------------------------------------------------
console.log('\n== §10 — signature ==');
check('signed with the wrong secret', outcome(good, WRONG_SECRET), WANT);
check('signature over a different message', outcome(`${h}.${p}.${hmac(`${h}.${p}.`).toString('base64url')}`), WANT);
check('signature truncated', outcome(`${h}.${p}.${s.slice(0, 8)}`), WANT);
check('signature empty', outcome(`${h}.${p}.`), WANT);
check('signature is not base64url', outcome(`${h}.${p}.!!!not-base64!!!`), WANT);
check('payload swapped, old signature kept', outcome(`${h}.${b64(claims({ role: 'owner' }))}.${s}`), WANT);

// ---------------------------------------------------------------------------
console.log('\n== §10 / D7 — exp is half-open: exp == now is expired ==');
check('expired one second ago', outcome(signToken(claims({ exp: nowSec() - 1 }), SECRET)), WANT);
check('exp exactly now', outcome(signToken(claims({ exp: nowSec() }), SECRET)), WANT);
check('exp missing', outcome(signToken(claims({ exp: undefined }), SECRET)), WANT);
check('exp is a string', outcome(signToken(claims({ exp: String(nowSec() + 900) }), SECRET)), WANT);
check('exp is null', outcome(signToken(claims({ exp: null }), SECRET)), WANT);
check('exp still valid -> accepted', outcome(signToken(claims({ exp: nowSec() + 120 }), SECRET)), 'accepted');

// ---------------------------------------------------------------------------
console.log('\n== §10 — issuer, audience, jti ==');
check('wrong iss', outcome(signToken(claims({ iss: 'evil' }), SECRET)), WANT);
check('iss missing', outcome(signToken(claims({ iss: undefined }), SECRET)), WANT);
check('wrong aud', outcome(signToken(claims({ aud: 'some-other-api' }), SECRET)), WANT);
check('aud missing', outcome(signToken(claims({ aud: undefined }), SECRET)), WANT);
check('jti missing', outcome(signToken(claims({ jti: undefined }), SECRET)), WANT);
check('jti empty', outcome(signToken(claims({ jti: '' }), SECRET)), WANT);

// ---------------------------------------------------------------------------
console.log('\n== §10 — a refresh token is not an access token ==');
check('opaque refresh token as bearer', outcome(randomBytes(32).toString('base64url')), WANT);
check('refresh token with a dot in it', outcome(`${randomBytes(16).toString('base64url')}.${randomBytes(16).toString('base64url')}`), WANT);

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
