# Security Testing Report

**Project:** Adaptive Secure Cloud Storage System
**Scope:** validation of the threat model defined in the project specification, against the implementation completed through Phase 13.

## Methodology

Three layers of evidence were used:
1. **Automated integration tests** — Node's built-in test runner (`node --test`) driving the real Express app against a real MySQL database, with Web Crypto (`node:crypto`'s `webcrypto`) standing in for the browser exactly as the real frontend would behave.
2. **A consolidated threat-model suite** (`tests/threatModel.integration.js`) that re-runs the most critical assertions from every phase in one place, tagged by threat number, so test output itself doubles as a traceability matrix.
3. **Manual verification** for anything automated tests cannot meaningfully prove (see `manual-pentest-checklist.md`).

## Threat-by-threat results

### Threat 1 — Attacker obtains S3 objects
**Expected:** attacker sees ciphertext, not plaintext.
**Evidence:**
- `tests/files.integration.js` → `data stored in S3 is ciphertext, never plaintext`
- `tests/threatModel.integration.js` → `[THREAT 1] downloaded bytes are never equal to the plaintext`
- Manual: AWS Console object downloaded and opened in a hex viewer (Phase 9, step 3) — confirmed unreadable.
**Result: PASS.** Ciphertext length is always plaintext + 16 bytes (GCM tag); plaintext never appears as a substring of stored bytes.

### Threat 2 — Attacker modifies ciphertext
**Expected:** AES-GCM authentication detects tampering.
**Evidence:**
- `tests/files.integration.js` → two dedicated tamper tests (wrong byte, wrong key)
- `tests/threatModel.integration.js` → tamper tests at three offsets (start/middle/auth tag)
**Result: PASS.** Every single-bit modification, at every tested offset, causes `decrypt()` to throw — GCM's authentication tag makes tampering cryptographically detectable, not just likely to be noticed.

### Threat 3 — Unauthorized user requests another user's file
**Expected:** backend authorization rejects the request.
**Evidence:**
- `tests/files.integration.js`, `tests/sharing.integration.js` → ownership and permission-level checks
- `tests/threatModel.integration.js` → `[THREAT 3]` sweeps all five file-scoped endpoints in one test
**Result: PASS.** A non-permitted user receives 404 (not 403) on metadata, download, key retrieval, delete, and permission-listing — the file's existence is never confirmed to someone without access.

### Threat 4 — Attacker obtains database records
**Expected:** sensitive encryption key material is not available as plaintext.
**Evidence:**
- `tests/auth.integration.js` → bcrypt hash format checks
- `tests/threatModel.integration.js` → `[THREAT 4]` sweeps every column of `user_keys`/`file_keys`
**Result: PASS, with one explicitly-documented exception.** `user_keys.public_key` is stored in plaintext — **by design**, since a public key is not a secret (see Phase 12). Every other key-bearing column (`wrapped_master_key`, `wrapped_private_key`, `wrapped_fek`, `recovery_key_hash`, `password_hash`) is either a one-way hash or AES/RSA ciphertext that fails to import as a usable key on its own.

### Threat 5 — Attacker obtains a user's JWT
**Expected:** token expiration/revocation/security controls limit abuse.
**Evidence:**
- `tests/auth.integration.js` → logout/revocation, 5-attempt lockout
- `tests/auth.test.js` → wrong secret, `alg: none`, expired token, purpose-claim mismatch (Phase 11)
- `tests/threatModel.integration.js` → explicit <=15-minute lifetime check; revoked token rejected on every protected route, not only `/me`
**Result: PASS, with a documented residual risk.** A stolen token remains valid for up to 15 minutes if the legitimate user does not log out. This is a deliberate, bounded trade-off (see Phase 5/11 "Honest limitations"), not an oversight — full instant cross-device revocation would require a `tokens_valid_after` timestamp, noted as future work.

### Threat 6 — User shares a file
**Expected:** only the authorized recipient gets permitted access.
**Evidence:**
- `tests/sharing.integration.js` → full suite (10 tests): correct recipient decrypts via their own private key, VIEW cannot download, CRITICAL capped at VIEW, revocation removes access, only the owner can manage sharing
- `tests/threatModel.integration.js` → `[THREAT 6]` three-stranger scenario
**Result: PASS.**

## Additional hardening validated (beyond the six named threats)

| Area | Test file | Result |
|---|---|---|
| SQL/script/path injection across every text input | `tests/injection.test.js` | PASS — every payload treated as inert data; no 500s, table always intact |
| Security headers (CSP, nosniff, no `X-Powered-By`) | `tests/hardening.test.js` | PASS |
| CORS restricted to the configured frontend origin | `tests/hardening.test.js` | PASS |
| Rate limiting actually active (not just configured) | `tests/hardening.test.js` | PASS |
| Oversized request bodies rejected before processing | `tests/hardening.test.js` | PASS |

## Summary table

| Threat | Status | Residual risk (if any) |
|---|---|---|
| 1. S3 object exposure | PASS | None identified |
| 2. Ciphertext tampering | PASS | None identified |
| 3. Cross-user file access | PASS | None identified |
| 4. Database compromise | PASS | Public keys are intentionally plaintext (non-secret by design) |
| 5. Stolen JWT | PASS | Up to 15-minute abuse window before natural expiry if not logged out |
| 6. Sharing misuse | PASS | Server trusts a user's claimed public key with no out-of-band verification (Phase 12 limitation) |

## Test execution summary

Run `npm run test:all` from `backend/` to execute every automated suite. As of this phase: **approximately 100 automated tests** across authentication, database, risk classification, adaptive policy, file sharing, audit logging, and the threat-model/injection/hardening suites added in this phase, all passing against a real MySQL database and (where applicable) real AWS S3.