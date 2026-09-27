-- RemoteOps — reference data. SQLite. Load AFTER schema.sql, BEFORE the org fixture.
-- Source of truth: PERMISSIONS.md §2 (catalogue) and §3 (role baselines).
--
-- Reference data, not user data. There is no API that mutates it.

BEGIN;

-- ---------------------------------------------------------------------------
-- Roles. `rank` is modification authority ONLY (D8). It must never be used to
-- answer a can() question — operator and auditor are unordered by permissions.
-- ---------------------------------------------------------------------------
INSERT INTO roles (key, rank, label) VALUES
  ('owner',    50, 'Owner'),
  ('admin',    40, 'Admin'),
  ('operator', 30, 'Operator'),
  ('auditor',  20, 'Auditor'),
  ('viewer',   10, 'Viewer');

-- ---------------------------------------------------------------------------
-- The 19 permissions, across six resources.
-- ---------------------------------------------------------------------------
INSERT INTO permissions (key, resource, action, description) VALUES
  ('device:list',          'device',  'list',          'See that devices exist; rows appear in the list'),
  ('device:view',          'device',  'view',          'Open device detail; the device is included in list responses'),
  ('device:control',       'device',  'control',       'Inject keyboard and mouse input'),
  ('device:terminal',      'device',  'terminal',      'Open a shell'),
  ('device:file_transfer', 'device',  'file_transfer', 'Push and pull files'),
  ('device:provision',     'device',  'provision',     'Enroll or decommission a device'),
  ('device:update',        'device',  'update',        'Rename, retag, reassign'),

  ('session:start',        'session', 'start',         'Open a remote session'),
  ('session:view',         'session', 'view',          'Watch a session without joining it'),
  ('session:terminate',    'session', 'terminate',     'End someone else''s session'),

  ('grant:create',         'grant',   'create',        'Create a grant'),
  ('grant:revoke',         'grant',   'revoke',        'Revoke a grant'),

  ('user:read',            'user',    'read',          'See the people list and profiles'),
  ('user:invite',          'user',    'invite',        'Invite a user'),
  ('user:role:update',     'user',    'role:update',   'Change a user''s role'),
  ('user:remove',          'user',    'remove',        'Remove or suspend a user'),

  ('audit:read',           'audit',   'read',          'Read the audit log'),

  ('org:update',           'org',     'update',        'Rename or reconfigure the org'),
  ('org:delete',           'org',     'delete',        'Delete the org');

-- ---------------------------------------------------------------------------
-- Permission PATTERNS: the superset that grants may reference.
-- Derived from the catalogue, plus the wildcards. Single source of truth stays
-- in `permissions`; this table exists only so the FK on grant_permissions can
-- accept 'device:*' while still rejecting 'device:teleport'.
-- ---------------------------------------------------------------------------
INSERT INTO permission_patterns (pattern) SELECT key FROM permissions;
INSERT INTO permission_patterns (pattern) VALUES
  ('device:*'), ('session:*'), ('grant:*'), ('user:*'), ('audit:*'), ('org:*'),
  ('*');

-- ---------------------------------------------------------------------------
-- Role baselines. Transcribed from the matrix in PERMISSIONS.md §3.
--
-- NOTE the auditor/operator pair: auditor has audit:read and lacks every control
-- permission; operator is the exact inverse. Roles are partially ordered, so any
-- implementation that ranks them by an integer level fails this pair.
-- ---------------------------------------------------------------------------

-- owner and admin: everything, except admin lacks org:delete
INSERT INTO role_permissions (role, permission)
SELECT r.key, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.key IN ('owner', 'admin')
  AND NOT (r.key = 'admin' AND p.key = 'org:delete');

-- operator: device operations + sessions, no user/grant/audit management
INSERT INTO role_permissions (role, permission) VALUES
  ('operator', 'device:list'),
  ('operator', 'device:view'),
  ('operator', 'device:control'),
  ('operator', 'device:terminal'),
  ('operator', 'device:file_transfer'),
  ('operator', 'session:start'),
  ('operator', 'session:view');

-- auditor: read-only, plus the audit log. No control of anything.
INSERT INTO role_permissions (role, permission) VALUES
  ('auditor', 'device:list'),
  ('auditor', 'device:view'),
  ('auditor', 'session:view'),
  ('auditor', 'user:read'),
  ('auditor', 'audit:read');

-- viewer: read-only, no audit log
INSERT INTO role_permissions (role, permission) VALUES
  ('viewer', 'device:list'),
  ('viewer', 'device:view'),
  ('viewer', 'session:view'),
  ('viewer', 'user:read');

COMMIT;

-- ---------------------------------------------------------------------------
-- Sanity check. Expect 19 permissions, and owner=19, admin=18, operator=7,
-- auditor=5, viewer=4. If this drifts, the baselines have diverged from the spec.
-- ---------------------------------------------------------------------------
-- SELECT role, count(*) AS n FROM role_permissions GROUP BY role ORDER BY n DESC;
-- SELECT count(*) FROM permissions;          -- expect 19
-- SELECT count(*) FROM permission_patterns;  -- expect 26 (19 concrete + 6 wildcards + '*')
