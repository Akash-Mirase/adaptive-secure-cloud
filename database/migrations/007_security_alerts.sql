USE adaptive_secure_cloud;

CREATE TABLE security_alerts (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id     BIGINT UNSIGNED NOT NULL,
  rule        VARCHAR(40)  NOT NULL,
  severity    ENUM('LOW','MEDIUM','HIGH') NOT NULL,
  message     VARCHAR(255) NOT NULL,
  details     JSON NULL,
  restriction ENUM('NONE','REQUIRE_STEP_UP','THROTTLE_DOWNLOADS') NOT NULL DEFAULT 'NONE',
  expires_at  DATETIME NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_alerts_user_rule (user_id, rule, created_at),
  KEY idx_alerts_created (created_at),
  CONSTRAINT fk_alerts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;