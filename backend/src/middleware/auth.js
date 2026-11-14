import asyncHandler from '../utils/asyncHandler.js'
import AppError from '../utils/AppError.js'
import * as users from '../models/user.model.js'
import * as revokedTokens from '../models/revokedToken.model.js'
import { verifyAccessToken } from '../services/auth.service.js'
import { logEvent } from '../services/audit.service.js'

// AUTHENTICATION: "who are you?"
// Expects header:  Authorization: Bearer <jwt>
// On success sets req.user (fresh from the database) and req.auth (token id + expiry).
export const authenticate = asyncHandler(async (req, res, next) => {
  const [scheme, token, extra] = (req.headers.authorization || '').split(' ')
  if (scheme !== 'Bearer' || !token || extra) {
    throw new AppError('Authentication required', 401)
  }

  const claims = verifyAccessToken(token) // signature, expiry, issuer, algorithm
  if (claims.purpose !== 'access') {
    throw new AppError('Invalid or expired token', 401)
  }
  const userId = Number.parseInt(claims.sub, 10)
  if (!Number.isSafeInteger(userId) || !claims.jti) {
    throw new AppError('Invalid or expired token', 401)
  }

  if (await revokedTokens.isRevoked(claims.jti)) {
    // Someone is replaying a token that was logged out. That is a security signal.
    await logEvent({
      userId,
      eventType: 'ACCESS_DENIED',
      result: 'DENIED',
      ipAddress: req.ip,
      details: { reason: 'REVOKED_TOKEN' }
    })
    throw new AppError('Invalid or expired token', 401)
  }

  // Re-load the user on every request: deleted accounts and changed roles apply at once.
  const user = await users.findById(userId)
  if (!user) throw new AppError('Invalid or expired token', 401)
      // "Log out everywhere" / post-recovery revocation: any token issued before the
  // user's cutoff is dead even though its signature and expiry are still valid.
  if (user.tokensValidAfter && claims.iat * 1000 < new Date(user.tokensValidAfter).getTime()) {
    await logEvent({
      userId, eventType: 'ACCESS_DENIED', result: 'DENIED', ipAddress: req.ip,
      details: { reason: 'TOKEN_ISSUED_BEFORE_REVOCATION' },
    });
    throw new AppError('Invalid or expired token', 401);
  }
  req.user = user
  req.auth = { jti: claims.jti, exp: claims.exp }
  next()
})

// AUTHORIZATION: "are you allowed?" (role level)
// Use AFTER authenticate:  router.get('/x', authenticate, requireRole('ADMIN'), handler)
// File-level checks (owner, shared permission) are added in Phase 6 and Phase 12.
export function requireRole (...allowedRoles) {
  return asyncHandler(async (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      await logEvent({
        userId: req.user?.id,
        eventType: 'ACCESS_DENIED',
        result: 'DENIED',
        ipAddress: req.ip,
        details: {
          reason: 'INSUFFICIENT_ROLE',
          required: allowedRoles,
          path: req.originalUrl.split('?')[0]
        }
      })
      throw new AppError('You do not have permission to do this', 403)
    }
    next()
  })
}
