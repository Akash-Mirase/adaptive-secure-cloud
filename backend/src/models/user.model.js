import { query } from '../config/env.js';

// Rows use snake_case (SQL); the rest of the app uses camelCase.
// The password hash is deliberately NOT part of the normal user object.
const toUser = (r) =>
  r && {
    id: r.id,
    name: r.name,
    email: r.email,
    role: r.role,
    failedLoginCount: r.failed_login_count,
    lockedUntil: r.locked_until,
    createdAt: r.created_at,
  };

export async function createUser({ name, email, passwordHash }, executor) {
  const result = await query(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
    [name, email, passwordHash],
    executor
  );
  return result.insertId;
}

export async function findById(id, executor) {
  const rows = await query('SELECT * FROM users WHERE id = ?', [id], executor);
  return toUser(rows[0]) || null;
}

export async function findByEmail(email, executor) {
  const rows = await query('SELECT * FROM users WHERE email = ?', [email], executor);
  return toUser(rows[0]) || null;
}

// Only the login flow should call this: it is the one place the hash is needed.
export async function findAuthRecordByEmail(email, executor) {
  const rows = await query('SELECT * FROM users WHERE email = ?', [email], executor);
  if (!rows[0]) return null;
  return { ...toUser(rows[0]), passwordHash: rows[0].password_hash };
}