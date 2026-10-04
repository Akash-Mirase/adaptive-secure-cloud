import asyncHandler from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import { getPolicy } from '../config/securityPolicies.js';
import { verifyStepUpToken } from '../services/auth.service.js';
import { logEvent } from '../services/audit.service.js';

// Applied AFTER authenticate (needs req.user) and loadFile (needs
// req.targetFile). This is the literal "adaptive" mechanism: the SAME route
// (download, get key) enforces different requirements depending on what is
// being accessed, decided fresh on every request from the file's stored
// riskLevel — not a fixed, blanket rule applied to all files alike.
export const enforceRiskPolicy = asyncHandler(async (req, res, next) => {
  const file = req.targetFile;
  const policy = getPolicy(file.riskLevel);
  req.policy = policy;

  // LOW / MEDIUM: nothing extra to check or log here — see
  // securityPolicies.js for why that is a deliberate choice, not an omission.
  if (!policy.requiresStepUp) return next();

  const token = req.headers['x-step-up-token'];
  if (!token) {
    await logEvent({
      userId: req.user.id, eventType: 'SECURITY_POLICY_APPLIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip,
      details: { riskLevel: file.riskLevel, requiresStepUp: true, reason: 'NO_STEP_UP_TOKEN' },
    });
    throw new AppError('Step-up verification required for this file', 428);
  }

  let claims;
  try {
    claims = verifyStepUpToken(token); // checks signature, algorithm, issuer, and the 'step-up' purpose claim
  } catch (err) {
    await logEvent({
      userId: req.user.id, eventType: 'SECURITY_POLICY_APPLIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip,
      details: { riskLevel: file.riskLevel, requiresStepUp: true, reason: 'INVALID_STEP_UP_TOKEN' },
    });
    throw err;
  }

  // A step-up token proves SOMEONE'S identity; it must still be THIS
  // request's authenticated user, not merely a well-signed token in general.
  if (String(claims.sub) !== String(req.user.id)) {
    await logEvent({
      userId: req.user.id, eventType: 'SECURITY_POLICY_APPLIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip,
      details: { riskLevel: file.riskLevel, reason: 'STEP_UP_TOKEN_SUBJECT_MISMATCH' },
    });
    throw new AppError('Step-up verification required for this file', 428);
  }

  // Freshness is checked against THIS FILE's policy window (via its
  // riskLevel), not the token's own longer outer expiry — this is what lets
  // CRITICAL demand a shorter re-verification interval than HIGH from the
  // exact same token, without issuing a different token per risk level.
  const ageSeconds = Math.floor(Date.now() / 1000) - claims.iat;
  if (ageSeconds > policy.stepUpValiditySeconds) {
    await logEvent({
      userId: req.user.id, eventType: 'SECURITY_POLICY_APPLIED', fileId: file.id, result: 'DENIED', ipAddress: req.ip,
      details: {
        riskLevel: file.riskLevel, reason: 'STEP_UP_EXPIRED_FOR_THIS_RISK_LEVEL',
        ageSeconds, allowedSeconds: policy.stepUpValiditySeconds,
      },
    });
    throw new AppError('Step-up verification required for this file', 428);
  }

  await logEvent({
    userId: req.user.id, eventType: 'SECURITY_POLICY_APPLIED', fileId: file.id, result: 'SUCCESS', ipAddress: req.ip,
    details: { riskLevel: file.riskLevel, requiresStepUp: true, ageSeconds },
  });
  next();
});