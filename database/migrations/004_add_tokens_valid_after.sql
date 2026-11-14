USE adaptive_secure_cloud;

-- Any JWT issued BEFORE this moment is rejected. NULL means no revocation yet.
ALTER TABLE users ADD COLUMN tokens_valid_after DATETIME NULL;