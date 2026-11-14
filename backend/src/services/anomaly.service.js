import { ANOMALY_RULES } from '../config/anomalyRules.js';
import * as alerts from '../models/securityAlert.model.js';

// Evaluates every rule for one user against their recent audit events.
// Dedupe: at most one alert per (user, rule) per window, so a burst doesn't spam alerts.
// This module deliberately does NOT call logEvent (avoids a circular import and a feedback loop).
export async function evaluateUser(userId, rules = ANOMALY_RULES, now = Date.now()) {
  const raised = [];
  for (const r of rules) {
    const since = new Date(now - r.windowMinutes * 60000);
    const count = await alerts.countEvents(userId, r.eventType, r.result, since);
    if (count < r.threshold) continue;
    if (await alerts.existsSince(userId, r.rule, since)) continue;

    const alert = {
      userId, rule: r.rule, severity: r.severity, message: r.describe(count, r.windowMinutes),
      details: { count, windowMinutes: r.windowMinutes, threshold: r.threshold },
      restriction: r.restriction,
      expiresAt: r.restriction === 'NONE' ? null : new Date(now + r.expiresMinutes * 60000),
    };
    await alerts.create(alert);
    raised.push(alert);
  }
  return raised;
}

export const hasRestriction = (userId, type) => alerts.hasActiveRestriction(userId, type);