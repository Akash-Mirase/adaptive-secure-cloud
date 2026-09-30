-- Phase 8: adds the recovery verifier used for unauthenticated account recovery.
-- Stores SHA-256(verifier). The verifier itself is derived from the recovery key
-- with HKDF in the browser and reveals nothing about the recovery WRAP key.
-- Run once against an existing Phase 1-7 database:
--   mysql -u root -p adaptive_secure_cloud < database/migrations/001_phase8_recovery_verifier.sql
USE adaptive_secure_cloud;
ALTER TABLE user_keys
  ADD COLUMN recovery_verifier CHAR(64) NULL AFTER recovery_iv;
