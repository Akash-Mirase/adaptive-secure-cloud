// The ONLY shape that may leave the inspection layer. Anything not listed here
// (text, matched values, offsets, page content) is dropped by construction.
const STATUSES = ['COMPLETE', 'PARTIAL', 'UNSUPPORTED', 'FAILED', 'TOO_LARGE'];

export function normalizeEvidence({ status, indicators = [], ocrUsed = false }) {
  const safeStatus = STATUSES.includes(status) ? status : 'FAILED';
  const clean = indicators.map(({ category, rule, count, strength }) => ({
    category, rule, strength, count: Math.max(1, Math.min(Math.trunc(count) || 1, 100000)),
  }));
  const highStrength = clean.some((i) => i.strength === 'HIGH');
  return {
    version: 1, status: safeStatus, indicators: clean, ocrUsed: Boolean(ocrUsed),
    reviewRecommended: safeStatus !== 'COMPLETE' && safeStatus !== 'UNSUPPORTED' ? true : highStrength,
  };
}
