USE adaptive_secure_cloud;

-- Row N = Master Key N, wrapped under Master Key N+1 (ciphertext only).
CREATE TABLE user_key_history (
  user_id     BIGINT UNSIGNED NOT NULL,
  key_version INT UNSIGNED NOT NULL,
  wrapped_key VARCHAR(255) NOT NULL,
  wrap_iv     VARCHAR(32)  NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, key_version),
  CONSTRAINT fk_key_history_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Which Master Key version wrapped this FEK. NULL for PUBLIC_KEY (shared) rows.
ALTER TABLE file_keys ADD COLUMN master_key_version INT UNSIGNED NULL;

-- Backfill is safe: no rotation existed before this migration, so every MASTER_KEY row is version 1.
UPDATE file_keys SET master_key_version = 1 WHERE wrap_type = 'MASTER_KEY' AND master_key_version IS NULL;