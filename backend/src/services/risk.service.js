import {
  FILE_TYPE_SCORES, DEFAULT_FILE_TYPE_SCORE,
  SENSITIVE_KEYWORDS, MAX_KEYWORD_SCORE,
  MAX_USER_SENSITIVITY_SCORE, RISK_THRESHOLDS,
} from '../config/riskRules.js';

// Compiled once at module load, not per-call, for a little efficiency and to
// fail fast if a regex pattern in riskRules.js is ever malformed.
const COMPILED_KEYWORDS = SENSITIVE_KEYWORDS.map(({ pattern, weight }) => ({
  regex: new RegExp(`(?:^|[^A-Za-z0-9])(${pattern})(?=$|[^A-Za-z0-9])`, 'i'),
  weight,
  pattern,
}));

function scoreFileType(mimeType) {
  return FILE_TYPE_SCORES[mimeType] ?? DEFAULT_FILE_TYPE_SCORE;
}

// Returns { score, matches: [{ pattern, weight }] } so the audit log (Phase 13)
// can record WHICH keywords fired, not just the final number — useful evidence
// for the report and for explaining a classification to a user who disputes it.
function scoreKeywords(filename) {
  const matches = COMPILED_KEYWORDS.filter(({ regex }) => regex.test(filename));
  const rawTotal = matches.reduce((sum, m) => sum + m.weight, 0);
  return {
    score: Math.min(rawTotal, MAX_KEYWORD_SCORE),
    matches: matches.map(({ pattern, weight }) => ({ pattern, weight })),
  };
}

function scoreUserSensitivity(userSensitivity) {
  const n = Number(userSensitivity);
  if (!Number.isInteger(n) || n < 0) return 0;
  return Math.min(n, MAX_USER_SENSITIVITY_SCORE);
}

function levelForScore(score) {
  return RISK_THRESHOLDS.find((t) => score >= t.min).level;
}

// The one function everything else calls. Pure and synchronous: same inputs
// always give the same output, which is what "transparent, rule-based" means
// in practice — no hidden state, nothing that varies between calls.
export function classifyFile({ originalName, mimeType, userSensitivity }) {
  const fileTypeScore = scoreFileType(mimeType);
  const { score: keywordScore, matches: keywordMatches } = scoreKeywords(originalName);
  const userSensitivityScore = scoreUserSensitivity(userSensitivity);

  const totalScore = fileTypeScore + keywordScore + userSensitivityScore;
  const riskLevel = levelForScore(totalScore);

  return {
    riskScore: totalScore,
    riskLevel,
    breakdown: { fileTypeScore, keywordScore, userSensitivityScore, keywordMatches },
  };
}