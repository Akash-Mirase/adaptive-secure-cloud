CREATE DATABASE IF NOT EXISTS adaptive_secure_cloud
  CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE adaptive_secure_cloud;

-- ---------------------------------------------------------------
-- users: identity + LOGIN password hash (bcrypt). This hash is NOT
-- used for encryption; encryption keys come from a separate KDF.
-- ---------------------------------------------------------------
CREATE TABLE users (
  id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name               VARCHAR(100)  NOT NULL,
  email              VARCHAR(255)  NOT NULL,
  password_hash      VARCHAR(255)  NOT NULL,
  role               ENUM('USER','ADMIN') NOT NULL DEFAULT 'USER',
  failed_login_count INT UNSIGNED  NOT NULL DEFAULT 0,
  locked_until       DATETIME      NULL,
  created_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- user_keys: the user's key hierarchy material (Phase 8).
-- Salt/iterations/IVs are non-secret. The Master Key is stored ONLY
-- as ciphertext (wrapped by the password-derived KEK, and optionally
-- by a recovery key). Values are base64 text.
-- ---------------------------------------------------------------
CREATE TABLE user_keys (
  user_id                     BIGINT UNSIGNED NOT NULL,
  kdf_algorithm               VARCHAR(32)  NOT NULL DEFAULT 'PBKDF2-SHA256',
  kdf_iterations              INT UNSIGNED NOT NULL,
  kdf_salt                    VARCHAR(64)  NOT NULL,
  wrapped_master_key          VARCHAR(255) NOT NULL,
  master_key_iv               VARCHAR(32)  NOT NULL,
  recovery_wrapped_master_key VARCHAR(255) NULL,
  recovery_iv                 VARCHAR(32)  NULL,
  recovery_key_hash           VARCHAR(60)  NULL,
  key_version                 INT UNSIGNED NOT NULL DEFAULT 1,
  created_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_user_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- files: metadata only. The file content lives in S3 as ciphertext.
-- id is a random UUID (it appears in S3 keys and URLs; unguessable IDs
-- are defense in depth, authorization is still the real control).
-- original_name is user-controlled DATA: it is never used in S3 keys
-- or file paths.
-- ---------------------------------------------------------------
CREATE TABLE files (
  id                CHAR(36)        NOT NULL,
  owner_id          BIGINT UNSIGNED NOT NULL,
  original_name     VARCHAR(255)    NOT NULL,
  stored_name       VARCHAR(64)     NOT NULL,
  mime_type         VARCHAR(127)    NOT NULL,
  file_size         BIGINT UNSIGNED NOT NULL,   -- plaintext size
  encrypted_size    BIGINT UNSIGNED NOT NULL,   -- ciphertext size (+16-byte GCM tag)
  s3_key            VARCHAR(255)    NOT NULL,
  risk_score        TINYINT UNSIGNED NOT NULL,
  risk_level        ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
  iv                VARCHAR(32)     NOT NULL,   -- file AES-GCM IV (not secret)
  key_metadata      JSON            NOT NULL,   -- algorithm, tag length, format version
  ciphertext_sha256 CHAR(64)        NULL,
  status            ENUM('PENDING','ACTIVE') NOT NULL DEFAULT 'PENDING',
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_files_s3_key (s3_key),
  KEY idx_files_owner_created (owner_id, created_at),
  KEY idx_files_risk_level (risk_level),
  CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- file_keys: one WRAPPED copy of a file's FEK per user who can open it.
-- Owner copy: wrapped with the owner's Master Key. Recipient copies
-- (Phase 12): wrapped with the recipient's public key.
-- Plaintext FEKs are NEVER stored.
-- ---------------------------------------------------------------
CREATE TABLE file_keys (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  file_id     CHAR(36)        NOT NULL,
  user_id     BIGINT UNSIGNED NOT NULL,
  wrapped_fek VARCHAR(1024)   NOT NULL,
  wrap_iv     VARCHAR(32)     NULL,             -- NULL for public-key wrapping
  wrap_type   ENUM('MASTER_KEY','PUBLIC_KEY') NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_file_keys_file_user (file_id, user_id),
  KEY idx_file_keys_user (user_id),
  CONSTRAINT fk_file_keys_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  CONSTRAINT fk_file_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- permissions: who may do what with a file.
-- ---------------------------------------------------------------
CREATE TABLE permissions (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  file_id    CHAR(36)        NOT NULL,
  user_id    BIGINT UNSIGNED NOT NULL,
  permission ENUM('VIEW','DOWNLOAD','EDIT','OWNER') NOT NULL,
  granted_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_permissions_file_user (file_id, user_id),
  KEY idx_permissions_user (user_id),
  CONSTRAINT fk_permissions_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  CONSTRAINT fk_permissions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_permissions_granted_by FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- audit_logs: append-only security trail.
-- No FK on file_id ON PURPOSE: the log must survive file deletion.
-- user_id becomes NULL if the user is deleted; the row is kept.
-- ---------------------------------------------------------------
CREATE TABLE audit_logs (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    BIGINT UNSIGNED NULL,
  event_type ENUM('REGISTER','LOGIN','LOGIN_FAILED','LOGOUT','UPLOAD','DOWNLOAD','DELETE',
                  'SHARE','UNSHARE','ACCESS_DENIED','KEY_OPERATION','RISK_CLASSIFICATION',
                  'SECURITY_POLICY_APPLIED','STEP_UP_VERIFICATION','INTEGRITY_FAILURE') NOT NULL,
  file_id    CHAR(36)    NULL,
  ip_address VARCHAR(45) NULL,
  result     ENUM('SUCCESS','FAILURE','DENIED') NOT NULL,
  details    JSON        NULL,
  created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_user_created (user_id, created_at),
  KEY idx_audit_event_created (event_type, created_at),
  KEY idx_audit_result_created (result, created_at),
  KEY idx_audit_file (file_id),
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- revoked_tokens: logout / revocation list for JWTs (Phase 5).
-- Rows can be purged once expires_at has passed.
-- ---------------------------------------------------------------
CREATE TABLE revoked_tokens (
  jti        CHAR(36)        NOT NULL,
  user_id    BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME        NOT NULL,
  PRIMARY KEY (jti),
  KEY idx_revoked_expires (expires_at),
  CONSTRAINT fk_revoked_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;