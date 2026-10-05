
# Adaptive Secure Cloud Storage System
### Using Client-Side Encryption and Risk-Based Key Management

An academic project demonstrating a secure cloud-storage web application where files are encrypted **in the browser, before upload**, and where the security controls applied to each file adapt automatically based on a transparent, rule-based assessment of that file's sensitivity.

---

## 1. Project Overview

Most "encrypted cloud storage" systems apply the same fixed security policy to every file regardless of its sensitivity — a holiday photo and a scanned passport are treated identically. This project implements **client-side AES-256-GCM encryption** (so the backend and AWS S3 only ever store ciphertext) combined with an **adaptive, risk-based security policy layer** that applies stronger controls — mandatory password re-verification, stricter sharing limits, enhanced audit monitoring — to files classified as higher risk, while leaving low-risk files with standard (but still fully encrypted) handling.

## 2. Problem Statement

Conventional cloud storage either:
- Trusts the server with plaintext (server-side encryption only), meaning a compromised backend or database exposes all user data, or
- Applies client-side encryption but treats every file identically, missing the opportunity to apply stronger access controls specifically where the data is most sensitive.

This project addresses both: plaintext never leaves the browser, and the system **differentiates its behavior** based on an assessed risk level, rather than applying one-size-fits-all security.

## 3. Objectives

1. Secure user registration, authentication, and authorization
2. Client-side AES-256-GCM encryption of every file before upload
3. A proper cryptographic key hierarchy (password → KDF → KEK → Master Key → per-file keys), not a single shared encryption key
4. Encrypted storage in AWS S3, with the server never seeing plaintext
5. Secure file download and in-browser decryption
6. Secure file sharing between users without ever exposing a user's Master Key to another party
7. A transparent, rule-based risk classification engine
8. An adaptive security policy layer that changes system behavior based on risk level
9. Comprehensive audit logging of all security-relevant events
10. Automated security testing validating a defined threat model
11. Empirical performance evaluation of the cryptographic and network pipeline

## 4. Novelty

**This project does not claim to have invented client-side encryption or encrypted cloud storage** — both are well-established techniques. The novelty claimed here is specific and narrower:

> **An adaptive, risk-based security policy layer integrated with client-side encrypted cloud storage**, where the system automatically assesses each file's sensitivity using transparent rules (file type, filename keyword matching, and user-declared sensitivity) and dynamically adjusts authentication requirements, sharing restrictions, and audit monitoring accordingly — without ever changing or weakening the underlying encryption algorithm itself.

| | Existing / conventional approach | This system |
|---|---|---|
| Security policy | Fixed — identical controls for every file | Risk-aware — controls scale with assessed sensitivity |
| Encryption | Often server-side only, or client-side with uniform handling | Client-side AES-256-GCM for every file, always |
| Sharing | Usually permission-based only | Permission-based **and** capped by the file's own risk level (e.g., a CRITICAL file can never be shared beyond VIEW-only) |
| Re-authentication | Typically session-based only | Risk-triggered step-up re-verification, with shorter freshness windows for higher-risk files |

Importantly, the adaptive layer **never makes AES-256-GCM "stronger" or "weaker"** — the cipher and key size are constant for every file regardless of risk level. What adapts is everything *around* the encryption: who can access it, how often they must re-prove their identity, how tightly sharing is restricted, and how closely access is monitored.

## 5. System Architecture (described)

```
USER (browser)
  │
  ▼
REACT CLIENT (Vite)
  ├─ Risk-sensitivity input (user-declared, one of three inputs to risk scoring)
  ├─ Client-side AES-256-GCM encryption (Web Crypto API)
  └─ Key hierarchy: Master Key + sharing keypair, unlocked per-session from the user's password
  │
  │  HTTPS — ciphertext only, plus non-secret metadata
  ▼
NODE.JS / EXPRESS BACKEND
  ├─ Authentication (JWT) & authorization (ownership + granted permissions)
  ├─ Risk classification (server-side, trusted — see rationale in §9)
  ├─ Adaptive policy enforcement (step-up verification, sharing caps)
  ├─ Audit logging (insert-only)
  └─ S3 operations (streamed, never decrypted)
  │
  ├──► MySQL — users, wrapped keys, file metadata, permissions, audit logs
  └──► AWS S3 — ciphertext objects only, least-privilege IAM, SSE-S3 at rest
```

**Trust boundary:** the backend, MySQL, and S3 are all treated as untrusted for *confidentiality* purposes. Only the browser ever holds plaintext file content or an unwrapped encryption key. The backend is still trusted for *authorization* and *policy enforcement* — it decides who may access what, and it is the system's only source of truth for a file's risk level (see §9 for why this specific function runs server-side despite the architecture's general client-side-first philosophy).

## 6. Technology Stack

**Frontend:** React, Vite, JavaScript, Bootstrap, React Router, Axios, Web Crypto API (`window.crypto.subtle`)
**Backend:** Node.js, Express.js, JWT (`jsonwebtoken`), `bcrypt`, `dotenv`, `multer`, AWS SDK v3 (`@aws-sdk/client-s3`, `@aws-sdk/lib-storage`)
**Database:** MySQL 8, `mysql2` (prepared statements only)
**Cloud:** AWS S3 (least-privilege IAM, SSE-S3, versioning, Block Public Access)
**Cryptography:** AES-256-GCM, PBKDF2-SHA256 (250,000 iterations), RSA-OAEP (2048-bit) for sharing, all via Web Crypto — no hand-rolled cryptographic primitives anywhere in the codebase

## 7. Project Structure

```
adaptive-secure-cloud/
├── frontend/           React app (components, pages, layouts, crypto/, services/, context/, hooks/)
├── backend/            Express app (config, controllers, middleware, models, routes, services, scripts, tests)
├── database/           schema.sql, seed.sql, migrations/
├── docs/               This documentation set, security/performance reports
├── .gitignore
├── README.md
└── docker-compose.yml  (optional local MySQL)
```

## 8. Installation and Setup

### Prerequisites
- Node.js 20+ and npm
- MySQL 8.x (local install or Docker)
- An AWS account with an S3 bucket and a least-privilege IAM user (see §8.4)
- Git

### 8.1 Clone and install

```bash
git clone <repo-url> adaptive-secure-cloud
cd adaptive-secure-cloud

cd backend && npm install
cd ../frontend && npm install
```

### 8.2 Database setup

```bash
mysql -u root -p < database/schema.sql
mysql -u root -p adaptive_secure_cloud < database/migrations/002_add_recovery_key_hash.sql
mysql -u root -p adaptive_secure_cloud < database/migrations/003_add_sharing_keys.sql
```

Create a least-privilege application database user (see `database/schema.sql` comments and Phase 4 of the build log for the exact `GRANT` statements) — **never run the application against the MySQL root account.**

### 8.3 Environment variables

Copy `backend/.env.example` to `backend/.env` and `frontend/.env.example` to `frontend/.env`, then fill in:

**`backend/.env`**
```env
NODE_ENV=development
PORT=4000
CORS_ORIGIN=http://localhost:5173

DB_HOST=localhost
DB_PORT=3306
DB_USER=asc_app
DB_PASSWORD=<your-app-db-password>
DB_NAME=adaptive_secure_cloud

JWT_SECRET=<generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))">
JWT_EXPIRES_IN=15m

AWS_ACCESS_KEY_ID=<IAM user access key, least-privilege, single bucket>
AWS_SECRET_ACCESS_KEY=<IAM user secret key>
AWS_REGION=<your bucket's region>
AWS_S3_BUCKET=<your bucket name>

MAX_UPLOAD_MB=100
```

**`frontend/.env`**
```env
VITE_API_BASE_URL=http://localhost:4000/api
```

**`.env` files are never committed to Git** — only `.env.example` templates are.

### 8.4 AWS S3 setup

1. Create an S3 bucket with **Block Public Access fully ON**, versioning enabled, and default SSE-S3 encryption enabled.
2. Create an IAM user with an inline policy scoped to **only** `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on that one bucket's objects, plus `s3:ListBucket` on the bucket itself. No managed/admin policies.
3. Generate an access key for that user and place it in `backend/.env`.

### 8.5 Running the application

```bash
# Terminal 1
cd backend
npm run dev

# Terminal 2
cd frontend
npm run dev
```

Frontend: `http://localhost:5173`. Backend health check: `http://localhost:4000/api/health`.

### 8.6 Creating the first admin account

```bash
cd backend
node src/scripts/promoteAdmin.js your-email@example.com
```

This is a one-off script, intentionally **not** an API endpoint, so there is no "become admin" route anywhere in the application's HTTP surface.

## 9. Core Workflows

### 9.1 Encryption workflow

```
User selects a file
  → Browser reads it via the File API
  → A new random 256-bit AES key (the File Encryption Key / FEK) is generated — ONE PER FILE, never reused
  → A new random 96-bit IV is generated — ONE PER ENCRYPTION OPERATION, never reused with the same key
  → AES-256-GCM encrypts the file entirely in the browser (window.crypto.subtle)
  → The FEK is wrapped (encrypted) under the user's Master Key
  → Only the ciphertext, the IV, the wrapped FEK, and non-secret metadata are sent to the backend
  → The backend validates the declared algorithm server-side (rejects anything that isn't AES-256-GCM) and stores the ciphertext in S3
```

The backend **never decrypts** at any point in the upload or download path. Downloading reverses the same flow: ciphertext is streamed from S3 to the browser, the FEK is fetched (still wrapped) and unwrapped locally using the Master Key, and only then is AES-GCM decryption performed — entirely client-side.

### 9.2 Key management workflow

The system maintains a strict key hierarchy, each layer only ever handled where it needs to be:

| Layer | Purpose | Where it's computed | Where it's stored |
|---|---|---|---|
| Login password hash | Prove identity at login | Server (bcrypt) | `users.password_hash` (one-way hash) |
| KDF (PBKDF2-SHA256, 250,000 rounds) | Turn the password into a Key Encryption Key | Browser only | Never stored |
| KEK (Key Encryption Key) | Unlock the Master Key | Browser only | Never stored, never leaves the browser |
| Master Key | Wrap/unwrap every file's FEK and the sharing private key | Generated once at registration, in the browser | Stored only **wrapped** (ciphertext) under the KEK |
| FEK (File Encryption Key) | Encrypt/decrypt one specific file | Generated fresh per file upload, in the browser | Stored only **wrapped** under the Master Key (owner) or the recipient's RSA public key (sharing) |
| Recovery Key | Emergency alternate way to unwrap the Master Key if the password is lost | Generated once at registration, shown to the user exactly once | Never stored; only a bcrypt hash of it is kept, to verify a future recovery attempt |
| RSA sharing keypair | Let another user receive a copy of a FEK without ever seeing the owner's Master Key | Generated once at registration | Public key stored in plaintext (non-secret); private key stored wrapped under the Master Key |

The login password is deliberately **not** used directly as an encryption key — it only ever proves identity to the server (via bcrypt) or feeds the client-side PBKDF2 derivation that produces the KEK. These are structurally different uses of the same secret, computed with different algorithms, for different purposes, and this distinction is intentional rather than incidental.

### 9.3 Password recovery

Because client-side encryption means the server never holds a usable key, losing both the account password **and** the one-time recovery key results in **permanent, by-design data loss** — there is no "forgot password" reset that preserves file access, because any such mechanism would require the server to be able to decrypt files, which would defeat the entire security model. This is stated explicitly to the user at registration and is a deliberate, correct consequence of genuine client-side encryption, not an oversight.

### 9.4 Risk-scoring workflow

Every uploaded file receives a transparent, rule-based score from three factors:

| Factor | Contribution | Max |
|---|---|---|
| File type (MIME type) | Structured documents (PDF, Word, Excel) score higher than plain images/text | 4 |
| Sensitive keywords in the filename | A configurable keyword list (`passport`, `salary`, `medical`, `confidential`, etc.), each match adds weight, capped | 4 |
| User-declared sensitivity | A dropdown the uploader fills in (0–3) | 3 |

```
Total score (0–11) → LOW (0–3) / MEDIUM (4–6) / HIGH (7–8) / CRITICAL (9+)
```

**Important architectural note:** classification runs **server-side**, not in the browser, even though the project's general philosophy is client-side-first. This is because the score drives real access-control decisions (see §9.5) — a client-reported score could trivially be forged by a modified browser or a raw API request declaring `riskLevel: LOW` for a file actually named `passport_confidential.pdf`. Running classification server-side, on inputs (filename, MIME type, user's own declared sensitivity) that are already necessarily sent to the server, keeps the resulting score trustworthy enough to gate real security behavior.

A second, equally important limitation: because file *content* is encrypted before the server ever sees it, classification **cannot** inspect file content — only metadata the user necessarily provides. This is a structural consequence of the zero-knowledge encryption model, not a missing feature.

### 9.5 Adaptive security policy

| Risk level | Step-up re-verification | Re-verify every... | Max sharing permission | Audit level |
|---|---|---|---|---|
| LOW | No | — | EDIT | Standard |
| MEDIUM | No | — | EDIT | Standard |
| HIGH | Yes | 10 minutes | DOWNLOAD | Enhanced |
| CRITICAL | Yes | 2 minutes | VIEW only, never public | Enhanced |

"Step-up verification" means the user must re-enter their password before the system will release a HIGH/CRITICAL file's ciphertext or decryption key, even within an already-authenticated session. **This is password re-confirmation, not multi-factor authentication** — there is no second, independent factor (phone, authenticator app, hardware key) anywhere in this system. This distinction is stated explicitly rather than implied to be MFA.

What adapts per risk level is strictly: authentication freshness requirements, sharing permission ceilings, and audit detail — **never** the encryption algorithm or key size, which remain AES-256-GCM / 256-bit for every file regardless of risk level.

### 9.6 Secure sharing

Sharing a file with another user never exposes the owner's Master Key. Instead:

```
Owner's FEK (unwrapped via the owner's own Master Key)
  → re-wrapped using RSA-OAEP under the RECIPIENT's public key (not secret, freely stored server-side)
  → stored as a second, separate wrapped-key row for that (file, recipient) pair
  → the recipient later unwraps it using their OWN private key (itself wrapped under their own Master Key)
```

Both users' Master Keys, and both private keys, never leave their respective browsers at any point. Revoking access deletes both the permission record and that recipient's wrapped-key row in one transaction.

## 10. Threat Model and Validation

| # | Threat | Expected result | Status |
|---|---|---|---|
| 1 | Attacker obtains S3 objects | Sees ciphertext only | **PASS** |
| 2 | Attacker modifies ciphertext | AES-GCM authentication detects tampering | **PASS** |
| 3 | Unauthorized user requests another user's file | Backend authorization rejects it (404, not 403 — existence is never confirmed) | **PASS** |
| 4 | Attacker obtains database records | No plaintext key material anywhere (public keys are the one intentional, documented exception) | **PASS** |
| 5 | Attacker obtains a user's JWT | Token expires within 15 minutes; logout revokes it immediately | **PASS**, with a documented residual risk (a stolen, not-yet-logged-out token remains valid until natural expiry) |
| 6 | User shares a file | Only the explicitly granted recipient gains access | **PASS** |

Full evidence, automated test mappings, and a manual penetration-testing checklist are in `docs/security-testing-report.md` and `docs/manual-pentest-checklist.md`.

## 11. Testing

Automated tests (Node's built-in test runner, run against a real MySQL database and, where applicable, real AWS S3):

```bash
cd backend
npm run test:all     # everything except the AWS-dependent storage contract suite
npm run test:storage # requires live AWS credentials
```

Suites cover: core app/error handling, database models and constraints, authentication (including lockout, revocation, token-purpose separation), file CRUD and ownership, client-side encryption correctness and tamper detection, key wrapping/unwrapping, AWS S3 integration, risk classification, adaptive policy enforcement, secure sharing, audit logging, a consolidated threat-model suite, an injection-payload sweep, and security-hardening checks (headers, CORS, rate limiting).

## 12. Performance Evaluation

Measured via `backend/scripts/benchmark.js` against the live stack (encryption/decryption are pure local CPU cost; upload/download include real network transfer to AWS S3). Full methodology, tables, and discussion are in `docs/performance-evaluation.md`. Headline finding: ciphertext overhead is a constant 16 bytes (the GCM authentication tag) regardless of file size, and cryptographic operations are consistently a small fraction of total processing time compared to network transfer — confirming the encryption layer is not the system's performance bottleneck.

## 13. Limitations

- Step-up verification is password re-confirmation, not true multi-factor authentication (no independent second factor exists in this system).
- A stolen JWT remains valid until its 15-minute expiry if the legitimate user does not log out; there is no instant cross-device revocation mechanism.
- Risk classification cannot inspect file content (a structural consequence of client-side encryption), only filename, MIME type, and user-declared sensitivity.
- Sharing trusts a recipient's public key as returned by the server, with no out-of-band identity/fingerprint verification (unlike, e.g., Signal's safety numbers).
- Revoking a shared file's access cannot retract a copy the recipient already downloaded and decrypted before revocation — inherent to any client-side-decryption system, not specific to this implementation.
- Losing both the account password and the recovery key results in permanent data loss by design — correctly reflecting genuine client-side encryption rather than a hidden server-side bypass.

## 14. Future Scope

- True multi-factor authentication (TOTP/authenticator app) as an alternative or addition to password-based step-up verification
- Per-user "tokens valid after" timestamp for instant cross-device session revocation
- Out-of-band public-key verification for sharing (safety-number-style comparison)
- File re-upload/versioning under the existing EDIT permission
- Concurrent-user load testing (e.g., with `k6` or `autocannon`) to complement the current per-operation latency benchmarks
- CSV/PDF export of audit logs
- Customer-managed KMS keys as an alternative to AWS-managed SSE-S3

## 15. Team

| Member | Primary responsibility |
|---|---|
| Member 1 | Frontend & client application (React, dashboard, upload/download UI, API integration, client crypto integration) |
| Member 2 | Cryptography & key management (AES-256-GCM, Web Crypto API, FEK/Master Key/KEK/KDF, recovery key, RSA sharing keys) |
| Member 3 | Backend, database & AWS (Express REST APIs, authentication/authorization, MySQL, S3, metadata, permissions) |
| Member 4 | Adaptive security, risk engine & testing (risk scoring, adaptive policy, security testing, threat model, performance evaluation) |

All members were expected to understand the full system end-to-end, not only their primary area.
```