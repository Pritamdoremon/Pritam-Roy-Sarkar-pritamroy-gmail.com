-- RemoteOps — Q1 schema. SQLite 3.37+ (STRICT tables).
-- Contract: PERMISSIONS.md (resolution) + AUTH-DATA-MODEL.md §5 (logical model).
--
-- Load order:  schema.sql  ->  reference.sql  ->  seed (orgs.json)
--
-- ############################################################################
-- # PRAGMA foreign_keys IS OFF BY DEFAULT IN SQLITE AND IS PER-CONNECTION.    #
-- # Set it on EVERY connection or every REFERENCES clause below silently      #
-- # does nothing — including the FK that rejects unknown permission strings   #
-- # (D19). The schema will load fine and enforce nothing.                     #
-- #                                                                           #
-- #   PRAGMA foreign_keys = ON;      -- per connection, not once per database  #
-- #   PRAGMA journal_mode = WAL;     -- persists; concurrent readers + 1 writer#
-- #   PRAGMA busy_timeout = 5000;    -- per connection; avoids SQLITE_BUSY     #
-- #   PRAGMA synchronous = NORMAL;   -- fine with WAL                          #
-- ############################################################################
--
-- DIALECT NOTES (vs the Postgres DDL in AUTH-DATA-MODEL.md §5):
--   citext      -> TEXT COLLATE NOCASE + a lowercase CHECK
--   TIMESTAMPTZ -> TEXT, ISO-8601 UTC with millis. Sorts lexicographically = chronologically.
--   JSONB       -> TEXT + json_valid() CHECK
--   BOOLEAN     -> INTEGER 0/1 (STRICT tables have no BOOLEAN)
--   now()       -> app-supplied, with strftime() as the default

BEGIN;

-- ============================================================================
-- Reference data
-- ============================================================================

CREATE TABLE roles (
  key   TEXT PRIMARY KEY,
  rank  INTEGER NOT NULL UNIQUE,
  label TEXT NOT NULL
) STRICT;
-- rank is modification authority ONLY (PERMISSIONS.md D8). NOT a permission level —
-- operator and auditor are unordered by permissions and this rank must NEVER be used
-- to answer a can() question.

CREATE TABLE permissions (
  key         TEXT PRIMARY KEY,
  resource    TEXT NOT NULL,
  action      TEXT NOT NULL,
  description TEXT NOT NULL
) STRICT;

-- A grant may name a wildcard pattern ('device:*', '*') as well as a concrete permission,
-- so grant_permissions cannot reference `permissions` directly — the FK would reject every
-- wildcard. This table is the superset: all 19 concrete permissions PLUS the patterns.
-- It is seeded from `permissions`, so there is still exactly one source of truth.
--
-- A typo like 'device:teleport' is still rejected, so D19 is preserved.
CREATE TABLE permission_patterns (
  pattern TEXT PRIMARY KEY
) STRICT;

-- The role baselines. Reference data: there is no API to mutate these.
CREATE TABLE role_permissions (
  role       TEXT NOT NULL REFERENCES roles(key) ON DELETE CASCADE,
  permission TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
  PRIMARY KEY (role, permission)
) STRICT, WITHOUT ROWID;

-- ============================================================================
-- Identity
-- ============================================================================

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  -- COLLATE BINARY is REQUIRED here. Without it the column's own NOCASE collation leaks
  -- into this '=' and the check always passes, so mixed-case emails get stored silently.
  CHECK (email = lower(email) COLLATE BINARY)
) STRICT;
-- Users are NEVER deleted (D15). No role column: authority lives on memberships
-- (AUTH-DATA-MODEL.md §4.1). No deleted_at, by design.

CREATE TABLE organizations (
  id                  TEXT PRIMARY KEY,
  name                TEXT NOT NULL,
  theme               TEXT NOT NULL,                -- feeds data-org-theme
  max_session_minutes INTEGER NOT NULL DEFAULT 60,  -- bounds grandfathering: PERMISSIONS.md §7.3
  created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at          TEXT
) STRICT;

-- The unit of identity within an org. Role and perm_version live HERE, not on users.
CREATE TABLE memberships (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES organizations(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  role         TEXT NOT NULL REFERENCES roles(key),
  status       TEXT NOT NULL CHECK (status IN ('invited','active','suspended','removed')),
  perm_version INTEGER NOT NULL DEFAULT 1,
  invited_by   TEXT REFERENCES users(id),
  joined_at    TEXT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (org_id, user_id)
) STRICT;
CREATE INDEX memberships_by_user ON memberships (user_id, status);

CREATE TABLE invites (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  email       TEXT NOT NULL COLLATE NOCASE,
  role        TEXT NOT NULL REFERENCES roles(key),
  token_hash  TEXT NOT NULL UNIQUE,          -- hash ONLY; the raw token is returned once
  invited_by  TEXT NOT NULL REFERENCES users(id),
  expires_at  TEXT NOT NULL,
  accepted_at TEXT,
  accepted_by TEXT REFERENCES users(id),
  revoked_at  TEXT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  CHECK (email = lower(email) COLLATE BINARY)   -- see the note on users.email
) STRICT;
-- Single-use and race-safe: enforced by the database, not by application logic.
CREATE UNIQUE INDEX one_live_invite_per_email
  ON invites (org_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- ============================================================================
-- Devices, grants, sessions
-- ============================================================================

CREATE TABLE devices (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES organizations(id),
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('macos','windows','linux','android','ios')),
  online     INTEGER NOT NULL DEFAULT 0 CHECK (online IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at TEXT
) STRICT;
CREATE INDEX devices_by_org ON devices (org_id) WHERE deleted_at IS NULL;

CREATE TABLE grants (
  id         TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES organizations(id),   -- org-scoped by construction
  user_id    TEXT NOT NULL REFERENCES users(id),
  device_id  TEXT REFERENCES devices(id),                  -- NULL = org-wide
  effect     TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  starts_at  TEXT,
  expires_at TEXT,                                         -- half-open: starts <= now < expires
  created_by TEXT NOT NULL REFERENCES users(id),
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  CHECK (expires_at IS NULL OR starts_at IS NULL OR expires_at > starts_at)
) STRICT;
CREATE INDEX grants_for_resolution ON grants (user_id, org_id) WHERE revoked_at IS NULL;

-- Normalized so an unknown permission string is a DB error, not a silent deny (D19).
-- References permission_patterns, not permissions, so wildcards are accepted.
-- This is the constraint that dies silently if PRAGMA foreign_keys is off.
CREATE TABLE grant_permissions (
  grant_id   TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
  permission TEXT NOT NULL REFERENCES permission_patterns(pattern),
  PRIMARY KEY (grant_id, permission)                       -- dedupes duplicates for free
) STRICT, WITHOUT ROWID;

CREATE TABLE sessions (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES organizations(id),
  user_id       TEXT NOT NULL REFERENCES users(id),
  device_id     TEXT NOT NULL REFERENCES devices(id),
  mode          TEXT NOT NULL CHECK (mode IN ('view','control','terminal')),
  state         TEXT NOT NULL CHECK (state IN ('connecting','active','ended')),
  end_reason    TEXT CHECK (end_reason IS NULL OR end_reason IN (
                  'user_stopped','user_suspended','membership_removed','device_transferred',
                  'admin_terminated','session_expired','superseded')),
  -- Load-bearing, not decorative: sessions are grandfathered, so this snapshot IS the
  -- authority for the life of the session (PERMISSIONS.md §7.1).
  authorized_by TEXT NOT NULL CHECK (json_valid(authorized_by)),
  started_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at    TEXT NOT NULL,                             -- started_at + org.max_session_minutes
  ended_at      TEXT
) STRICT;
CREATE INDEX sessions_active_by_user ON sessions (user_id, org_id) WHERE state = 'active';

-- D10 as a database guarantee: one exclusive session per device. Two parallel `control`
-- requests cannot both commit. `view` is deliberately excluded.
CREATE UNIQUE INDEX one_exclusive_session_per_device
  ON sessions (device_id)
  WHERE state = 'active' AND mode IN ('control','terminal');

-- ============================================================================
-- Audit — append only
-- ============================================================================

CREATE TABLE audit_events (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  actor_id    TEXT REFERENCES users(id),
  action      TEXT NOT NULL,
  target_type TEXT,
  target_id   TEXT,
  result      TEXT NOT NULL CHECK (result IN ('allow','deny')),
  reason_code TEXT,
  request_id  TEXT,
  at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;
CREATE INDEX audit_by_org ON audit_events (org_id, at DESC);

-- Invariant 10, enforced by the storage layer rather than by convention.
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only (PERMISSIONS.md invariant 10)');
END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only (PERMISSIONS.md invariant 10)');
END;

-- ============================================================================
-- Refresh tokens (opaque, rotating, revocable — D12)
-- ============================================================================

CREATE TABLE refresh_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,
  family_id  TEXT NOT NULL,        -- rotation lineage; reuse of an old token kills the family
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;
CREATE INDEX refresh_by_family ON refresh_tokens (family_id);

COMMIT;
