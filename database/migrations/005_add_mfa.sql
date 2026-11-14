USE adaptive_secure_cloud;

CREATE TABLE user_mfa (
  user_id           BIGINT UNSIGNED NOT NULL,
  secret_ciphertext VARCHAR(255) NOT NULL,
  secret_iv         VARCHAR(32)  NOT NULL,
  secret_tag        VARCHAR(32)  NOT NULL,
  enabled           TINYINT(1)   NOT NULL DEFAULT 0,
  last_used_step    BIGINT       NULL,
  failed_attempts   INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until      DATETIME     NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE mfa_recovery_codes (
  id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    BIGINT UNSIGNED NOT NULL,
  code_hash  CHAR(64) NOT NULL,
  used_at    DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_recovery_hash (code_hash),
  KEY idx_recovery_user (user_id),
  CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;