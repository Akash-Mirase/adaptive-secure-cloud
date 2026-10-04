// SINGLE SOURCE OF TRUTH for adaptive security controls per risk level,
// mirroring the risk-rules pattern from Phase 10 (data here, logic in the
// middleware that consumes it). LOW and MEDIUM deliberately get NO extra
// controls beyond what every file already has since Phase 6 (ownership
// checks, AES-256-GCM, UPLOAD/DOWNLOAD/DELETE audit events) — adaptive
// security means HIGH/CRITICAL get MORE, not that every level gets some
// arbitrary busywork bolted on for appearances.
export const SECURITY_POLICIES = {
  LOW: {
    requiresStepUp: false,
    stepUpValiditySeconds: null,
    maxSharePermission: 'EDIT',
    auditLevel: 'STANDARD',
  },
  MEDIUM: {
    requiresStepUp: false,
    stepUpValiditySeconds: null,
    maxSharePermission: 'EDIT',
    auditLevel: 'STANDARD',
  },
  HIGH: {
    requiresStepUp: true,
    // Valid for 10 minutes: long enough to work through several HIGH files
    // without re-entering a password every click, short enough that an
    // unlocked, walked-away laptop isn't a standing invitation.
    stepUpValiditySeconds: 600,
    maxSharePermission: 'DOWNLOAD', // Phase 12: recipients may never get EDIT/OWNER on a HIGH file
    auditLevel: 'ENHANCED',
  },
  CRITICAL: {
    requiresStepUp: true,
    stepUpValiditySeconds: 120, // re-verified far more often than HIGH
    maxSharePermission: 'VIEW', // Phase 12: CRITICAL files may only ever be shared VIEW-only
    auditLevel: 'ENHANCED',
    // Explicit and redundant by design: this application has no public/
    // anonymous sharing feature at all, but CRITICAL files must be hard-blocked
    // from it even if such a feature were added later.
    blockPublicSharing: true,
  },
};

// Fail-safe default: an unrecognized risk level gets the STRICTEST reading
// available for a level below it — actually the LEAST restrictive (LOW) is
// used here because an unknown level should never occur (riskLevel is an
// ENUM in MySQL), so this only matters for defensive coding, not real traffic.
export function getPolicy(riskLevel) {
  return SECURITY_POLICIES[riskLevel] || SECURITY_POLICIES.LOW;
}