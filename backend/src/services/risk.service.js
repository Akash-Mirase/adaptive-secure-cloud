// import {
//   FILE_TYPE_SCORES, DEFAULT_FILE_TYPE_SCORE,
//   SENSITIVE_KEYWORDS, MAX_KEYWORD_SCORE,
//   MAX_USER_SENSITIVITY_SCORE, RISK_THRESHOLDS,
// } from '../config/riskRules.js';

import * as R from '../config/riskRules.js';

const COMPILED_KEYWORDS = R.SENSITIVE_KEYWORDS.map(({ pattern, weight }) => ({
  regex: new RegExp(`(?:^|[^A-Za-z0-9])(${pattern})(?=$|[^A-Za-z0-9])`, 'i'),
  weight, pattern,
}));
const INSPECTABLE_MIME = new Set([
  'application/pdf', 'text/plain', 'text/csv', 'image/png', 'image/jpeg', 'image/gif', 'image/webp',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);

const extensionOf = (name) => {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(String(name || ''));
  return m ? m[1].toLowerCase() : null;
};

function scoreUserSensitivity(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) return 0;
  return Math.min(n, R.MAX_USER_SENSITIVITY);
}

function scoreKeywords(filename) {
  const matches = COMPILED_KEYWORDS.filter(({ regex }) => regex.test(filename));
  const raw = matches.reduce((s, m) => s + m.weight, 0);
  return { score: Math.min(raw, R.MAX_KEYWORD_SCORE), matches: matches.map(({ pattern, weight }) => ({ pattern, weight })) };
}

// File type uses the HIGHER of (declared MIME, MIME implied by extension), so declaring a
// harmless MIME for a PDF cannot lower the score. Mismatch/unknown add metadata points.
function scoreTypeAndMetadata(mimeType, originalName) {
  const ext = extensionOf(originalName);
  const extMime = ext ? R.EXTENSION_MIME[ext] : undefined;
  const declaredKnown = mimeType in R.FILE_TYPE_SCORES;
  const declaredScore = R.FILE_TYPE_SCORES[mimeType] ?? R.DEFAULT_FILE_TYPE_SCORE;
  const extScore = extMime ? R.FILE_TYPE_SCORES[extMime] : 0;
  const fileTypeScore = Math.min(Math.max(declaredScore, extScore), R.MAX_FILE_TYPE_SCORE);

  const notes = [];
  let metadata = 0;
  if (!declaredKnown && !extMime) { metadata += R.METADATA_UNKNOWN_TYPE_POINTS; notes.push('UNRECOGNIZED_FILE_TYPE'); }
  if (declaredKnown && extMime && declaredKnown && extMime !== mimeType) { metadata += R.METADATA_MISMATCH_POINTS; notes.push('EXTENSION_MIME_MISMATCH'); }
  if (!declaredKnown && extMime) notes.push('DECLARED_TYPE_NOT_RECOGNIZED'); // type score already taken from extension
  return { fileTypeScore, metadata, notes, ext, extMime };
}

// Content score: ONE contribution per category (no stacking of rules inside a category),
// keyword-only (LOW strength) evidence earns half, many occurrences add a bonus point, total capped.
function scoreContent(indicators) {
  const byCat = new Map();
  for (const i of indicators) {
    const c = byCat.get(i.category) || { strength: 'LOW', count: 0, rules: [] };
    if (R.EVIDENCE_STRENGTHS.indexOf(i.strength) > R.EVIDENCE_STRENGTHS.indexOf(c.strength)) c.strength = i.strength;
    c.count += i.count; c.rules.push(i.rule);
    byCat.set(i.category, c);
  }
  let total = 0;
  const categories = [];
  for (const [category, c] of byCat) {
    let pts = R.CATEGORY_POINTS[category] ?? 0;
    if (c.strength === 'LOW') pts = Math.floor(pts / R.LOW_STRENGTH_DIVISOR);
    if (pts > 0 && c.count >= R.COUNT_BONUS_THRESHOLD) pts += R.COUNT_BONUS_POINTS;
    total += pts;
    categories.push({ category, rules: c.rules, count: c.count, strength: c.strength, points: pts });
  }
  return { score: Math.min(total, R.MAX_CONTENT_SCORE), categories };
}

const levelForScore = (score) => R.RISK_THRESHOLDS.find((t) => score >= t.min).level;
const higherLevel = (a, b) => (R.LEVEL_ORDER.indexOf(a) >= R.LEVEL_ORDER.indexOf(b) ? a : b);

// Pure and deterministic. `contentEvidence` must already be validated by parseContentEvidence.
export function classifyFile({ originalName = '', mimeType = '', userSensitivity = 0, contentEvidence, context } = {}) {
  const name = String(originalName);
  const mime = String(mimeType);
  const evidence = contentEvidence || { status: 'NOT_PROVIDED', indicators: [], ocrUsed: false, reviewRecommended: false };

  const userSensitivityScore = scoreUserSensitivity(userSensitivity);
  const { fileTypeScore, metadata, notes, extMime } = scoreTypeAndMetadata(mime, name);
  const { score: keywordScore, matches: keywordMatches } = scoreKeywords(name);
  const content = scoreContent(evidence.indicators);

  // Uncertainty: for a type we normally inspect, a failed/partial/too-large scan is not "clean".
  let metadataScore = metadata;
  const inspectable = INSPECTABLE_MIME.has(mime) || INSPECTABLE_MIME.has(extMime);
  if (inspectable && ['FAILED', 'PARTIAL', 'TOO_LARGE'].includes(evidence.status)) {
    metadataScore += R.METADATA_UNINSPECTED_POINTS;
    notes.push('CONTENT_NOT_FULLY_INSPECTED');
  }
  metadataScore = Math.min(metadataScore, R.MAX_METADATA_SCORE);

  const contextScore = context?.activeAlert ? R.CONTEXT_ACTIVE_ALERT_POINTS : 0;

  const riskScore = Math.min(
    userSensitivityScore + fileTypeScore + metadataScore + keywordScore + content.score + contextScore,
    R.MAX_RISK_SCORE
  );
  const scoreLevel = levelForScore(riskScore);
  const floorLevel = R.SENSITIVITY_FLOOR[userSensitivityScore];
  const contentFloorHit = evidence.indicators.some((i) => i.strength === 'HIGH' && R.CONTENT_FLOOR_RULES.includes(i.rule));
  const contentFloor = contentFloorHit ? R.CONTENT_FLOOR_LEVEL : 'LOW';
  const riskLevel = higherLevel(higherLevel(scoreLevel, floorLevel), contentFloor);
  const floorApplied = riskLevel !== scoreLevel;

  const explanation = [];
  explanation.push(`You declared "${R.SENSITIVITY_LABELS[userSensitivityScore]}" sensitivity.`);
  if (content.categories.length) {
    explanation.push(`Content inspection found indicators in: ${content.categories.map((c) => c.category.toLowerCase().replace('_', ' ')).join(', ')}.`);
  } else if (evidence.status === 'COMPLETE') {
    explanation.push('Content inspection found no sensitive-data indicators (this does not prove the file is harmless).');
  } else {
    explanation.push(`Content inspection status: ${evidence.status.replace('_', ' ').toLowerCase()}.`);
  }
  if (keywordMatches.length) explanation.push('The file name contains sensitive keywords.');
  if (notes.length) explanation.push('File metadata raised the score or flagged uncertainty.');
  if (floorApplied) {
    explanation.push(contentFloorHit && R.LEVEL_ORDER.indexOf(contentFloor) >= R.LEVEL_ORDER.indexOf(floorLevel)
      ? `The level was raised to ${riskLevel} because a strongly validated sensitive-data pattern was found.`
      : `The level was raised to ${riskLevel} because your declared sensitivity sets a minimum.`);
  }

  return {
    riskScore, riskLevel, floorApplied, ruleVersion: R.RULE_VERSION,
    breakdown: {
      userSensitivityScore, fileTypeScore, metadataScore, keywordScore,
      contentScore: content.score, contextScore, keywordMatches,
      contentCategories: content.categories, metadataNotes: notes,
      inspectionStatus: evidence.status, ocrUsed: evidence.ocrUsed,
      reviewRecommended: evidence.reviewRecommended || notes.includes('CONTENT_NOT_FULLY_INSPECTED'),
      floorLevel, contentFloor, scoreLevel,
    },
    explanation,
  };
}
