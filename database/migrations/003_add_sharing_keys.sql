USE adaptive_secure_cloud;

-- Public key: NOT a secret — it's meant to be readable by anyone who needs to
-- share a file with this user. Stored as base64 SPKI (RSA-OAEP, 2048-bit).
-- Private key: wrapped (ciphertext) under the user's own MASTER KEY (not the
-- KEK). This is a deliberate choice: a password change or recovery (Phase 8)
-- only re-wraps the Master Key, so the private key's own wrapping NEVER needs
-- to be touched when the password changes.
ALTER TABLE user_keys
  ADD COLUMN public_key          VARCHAR(1024) NULL,
  ADD COLUMN wrapped_private_key VARCHAR(4096) NULL,
  ADD COLUMN private_key_iv      VARCHAR(32)   NULL;