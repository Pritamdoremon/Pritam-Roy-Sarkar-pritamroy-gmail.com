// Append-only audit writes.
//
// YOURS TO WRITE. This file ships as a stub.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Two things the spec is explicit about (BRIEF.md §4, PERMISSIONS.md §8):
//
//   - DENIED attempts are recorded, not just successes. A log that only holds
//     successes cannot answer "who tried to change what".
//   - a single action produces a single row. Write the success row inside the same
//     transaction as the change it describes; do not also log the allow from a wrapper.
//
// Schema columns: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
// result ('allow'|'deny'), reason_code, request_id, at.

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/audit.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  throw todo('audit');
}

// Run fn(); if it refuses with a permission error, record the denial before rethrowing.
export function auditDenials(db, ctx, meta, fn) {
  throw todo('auditDenials');
}
