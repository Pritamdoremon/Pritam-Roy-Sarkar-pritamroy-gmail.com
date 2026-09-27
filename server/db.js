import Database from 'better-sqlite3';

// ############################################################################
// # These four pragmas are NOT optional and are NOT a one-time setup step.    #
// # foreign_keys is OFF by default in SQLite and is PER-CONNECTION.           #
// # Without it the schema loads fine and enforces nothing — including the FK  #
// # that rejects unknown permission strings (PERMISSIONS.md D19).             #
// ############################################################################
export function openDatabase(file = process.env.DATABASE_FILE ?? 'app.db') {
  const db = new Database(file);

  db.pragma('foreign_keys = ON');    // per connection. omitting this is the #1 SQLite footgun
  db.pragma('journal_mode = WAL');   // persists in the file: concurrent readers + one writer
  db.pragma('busy_timeout = 5000');  // per connection: wait rather than throw SQLITE_BUSY
  db.pragma('synchronous = NORMAL'); // safe with WAL

  return db;
}

// Timestamps are ISO-8601 UTC with millis, so lexicographic order == chronological
// order and plain string comparison works in SQL. Matches the schema defaults.
export const nowIso = () => new Date().toISOString();

export function newId(prefix) {
  const rand = crypto.randomUUID().replaceAll('-', '').slice(0, 16);
  return `${prefix}_${rand}`;
}

// A tiny helper so every write that touches authorization can bump the version in
// the same breath. Permission changes take effect on the NEXT request (PERMISSIONS.md
// §7.4) — the version is how the server notices.
export function bumpPermVersion(db, { orgId, userId }) {
  db.prepare(
    `UPDATE memberships SET perm_version = perm_version + 1
      WHERE org_id = ? AND user_id = ?`
  ).run(orgId, userId);
}
