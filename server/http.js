// HTTP helpers: the error type, body reading, and response writing.
//
// Every error response has the same shape (PERMISSIONS.md §10):
//   { error: { code, message, reason, requestId } }
// Keep it identical everywhere. The "doesn't exist" and "belongs to another org"
// responses must be indistinguishable — see PERMISSIONS.md §6.

export class HttpError extends Error {
  constructor(status, code, message, reason = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

export const badRequest = (msg, reason = null) => new HttpError(400, 'VALIDATION', msg, reason);
export const unauthenticated = (msg = 'not authenticated') => new HttpError(401, 'UNAUTHENTICATED', msg);
export const tokenStale = () => new HttpError(401, 'TOKEN_STALE', 'token is stale; refresh and retry');
export const forbidden = (msg = 'forbidden', reason = 'missing_permission') => new HttpError(403, 'FORBIDDEN', msg, reason);
export const selfRoleChange = () => new HttpError(403, 'SELF_ROLE_CHANGE', 'you cannot change your own role');
export const notFound = (msg = 'not found') => new HttpError(404, 'NOT_FOUND', msg);
export const conflict = (msg, code = 'CONFLICT') => new HttpError(409, code, msg);
export const lastOwner = () => new HttpError(409, 'LAST_OWNER', 'the org must always have at least one owner');
export const deviceBusy = (msg = 'device already has an exclusive session') => new HttpError(409, 'DEVICE_BUSY', msg);
export const gone = (msg = 'invite is no longer valid') => new HttpError(410, 'GONE', msg);

// Normalise a client-supplied timestamp to the canonical form the schema stores and
// compares: ISO-8601 UTC ending in 'Z'.
//
// This matters because timestamps are TEXT and compared LEXICOGRAPHICALLY. A client that
// sends '...+00:00' gets silently mis-ordered against '...Z' — '+' sorts before 'Z' — so an
// unexpired grant would be treated as already expired. Accept-and-normalise, or reject;
// never store a form that does not compare correctly.
export function normalizeTs(value, field) {
  if (value === null || value === undefined) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw badRequest(`${field} is not a valid timestamp`);
  return d.toISOString();
}

export function send(res, status, body) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

export function sendError(res, err, requestId) {
  const status = err instanceof HttpError ? err.status : 500;
  const code = err instanceof HttpError ? err.code : 'INTERNAL';

  // Never leak internals, and never echo request bodies — they can contain
  // stream keys and invite tokens.
  const message = err instanceof HttpError ? err.message : 'internal error';

  if (!(err instanceof HttpError)) {
    console.error(`[${requestId}] unhandled:`, err);
  }

  send(res, status, { error: { code, message, reason: err.reason ?? null, requestId } });
}

const MAX_BODY = 1_000_000; // 1 MB

export function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(badRequest('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (size === 0) return resolve({});
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(badRequest('body must be a JSON object'));
        }
        resolve(parsed);
      } catch {
        reject(badRequest('malformed JSON body'));
      }
    });

    req.on('error', reject);
  });
}
