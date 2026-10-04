// Usage: node src/scripts/promoteAdmin.js user@example.com
// Run once, by hand, outside the normal request/response flow — deliberately
// NOT an API endpoint, so there is no "become admin" route for anyone to probe.
import { query, closePool } from '../config/env.js';

const email = process.argv[2];
if (!email) {
  console.error('Usage: node src/scripts/promoteAdmin.js <email>');
  process.exit(1);
}

const result = await query("UPDATE users SET role = 'ADMIN' WHERE email = ?", [email]);
if (result.affectedRows === 0) {
  console.error(`No user found with email: ${email}`);
} else {
  console.log(`${email} is now an ADMIN.`);
}
await closePool();