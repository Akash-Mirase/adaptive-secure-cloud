import {
  EVIDENCE_CATEGORIES, EVIDENCE_RULES, EVIDENCE_STRENGTHS, EVIDENCE_STATUSES,
  MAX_EVIDENCE_INDICATORS, MAX_EVIDENCE_COUNT,
} from '../config/riskRules.js';

// The browser's inspection result is UNTRUSTED input. This function accepts only a
// fixed schema of enums and bounded integers, so it can never carry file text or any
// raw value: free-form strings are impossible by construction.
// Returns { ok:true, evidence } or { ok:false, reason }.
export function parseContentEvidence(raw) {
  if (raw === undefined || raw === null || raw === '') {
    return { ok: true, evidence: { status: 'NOT_PROVIDED', indicators: [], ocrUsed: false, reviewRecommended: false } };
  }
  let obj = raw;
  if (typeof raw === 'string') {
    if (raw.length > 8000) return { ok: false, reason: 'contentEvidence is too large' };
    try { obj = JSON.parse(raw); } catch { return { ok: false, reason: 'contentEvidence must be valid JSON' }; }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { ok: false, reason: 'contentEvidence must be an object' };
  if (obj.version !== 1) return { ok: false, reason: 'unsupported contentEvidence version' };
  if (!EVIDENCE_STATUSES.includes(obj.status)) return { ok: false, reason: 'invalid inspection status' };
  if (!Array.isArray(obj.indicators) || obj.indicators.length > MAX_EVIDENCE_INDICATORS) {
    return { ok: false, reason: 'invalid indicators list' };
  }

  const seen = new Set();
  const indicators = [];
  for (const i of obj.indicators) {
    if (!i || typeof i !== 'object') return { ok: false, reason: 'invalid indicator' };
    if (!EVIDENCE_CATEGORIES.includes(i.category)) return { ok: false, reason: 'invalid indicator category' };
    if (!EVIDENCE_RULES.includes(i.rule)) return { ok: false, reason: 'invalid indicator rule' };
    if (!EVIDENCE_STRENGTHS.includes(i.strength)) return { ok: false, reason: 'invalid indicator strength' };
    if (!Number.isInteger(i.count) || i.count < 1 || i.count > MAX_EVIDENCE_COUNT) return { ok: false, reason: 'invalid indicator count' };
    if (seen.has(i.rule)) return { ok: false, reason: 'duplicate indicator rule' }; // no double counting
    seen.add(i.rule);
    indicators.push({ category: i.category, rule: i.rule, count: i.count, strength: i.strength }); // copies ONLY known fields
  }
  return {
    ok: true,
    evidence: {
      status: obj.status, indicators,
      ocrUsed: obj.ocrUsed === true, reviewRecommended: obj.reviewRecommended === true,
    },
  };
}
