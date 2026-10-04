// Holds the short-lived step-up token in memory for this tab only, mirroring
// masterKeySession.js from Phase 8 (never persisted to storage, cleared on
// logout). The server — not this module — decides whether the token is still
// fresh enough for a given file's risk level.
let stepUpToken = null;

export function setStepUpToken(token) { stepUpToken = token; }
export function getStepUpToken() { return stepUpToken; }
export function clearStepUpToken() { stepUpToken = null; }