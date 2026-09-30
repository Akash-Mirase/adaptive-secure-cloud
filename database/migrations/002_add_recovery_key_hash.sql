USE adaptive_secure_cloud;

-- Stores a bcrypt hash of the user's recovery key so the server can VERIFY a
-- recovery attempt (rate-limit and reject wrong recovery keys) without ever
-- storing the recovery key itself. The recovery key's actual job — unwrapping
-- the Master Key — happens entirely client-side and never touches this hash.
ALTER TABLE user_keys
  ADD COLUMN recovery_key_hash VARCHAR(60) NULL AFTER recovery_iv;