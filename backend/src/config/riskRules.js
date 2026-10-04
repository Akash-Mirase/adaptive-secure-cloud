// SINGLE SOURCE OF TRUTH for risk scoring. Change weights or lists here only;
// risk.service.js contains no hard-coded numbers itself. This is what the
// spec means by "make the scoring rules configurable."

// File type score: grouped by how commonly that type carries sensitive
// structured data (documents, archives) vs. rarely does (plain images, text).
export const FILE_TYPE_SCORES = {
  // High: structured documents commonly used for IDs, contracts, records
  'application/pdf': 3,
  'application/msword': 3,
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 3,
  'application/vnd.ms-excel': 3,
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 3,
  // Medium: archives can bundle anything, presentations occasionally sensitive
  'application/zip': 2,
  'application/vnd.ms-powerpoint': 2,
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': 2,
  // Low: media and plain text are less commonly primary carriers of formal sensitive records
  'image/png': 1,
  'image/jpeg': 1,
  'image/gif': 1,
  'image/webp': 1,
  'text/plain': 1,
  'text/csv': 2, // CSV can be exported financial/personal data — scored slightly higher than plain text
};
export const DEFAULT_FILE_TYPE_SCORE = 1; // unknown/other allowed types
export const MAX_FILE_TYPE_SCORE = 4; // headroom above the table's current max, for future high-risk types

// Sensitive keyword list: matched against the filename only (case-insensitive,
// word-boundary so "passport" doesn't match "passportable"). Each match adds
// its weight; total keyword contribution is capped at MAX_KEYWORD_SCORE so a
// contrived filename ("passport_medical_salary_confidential.pdf") cannot
// blow past the intended scale.
export const SENSITIVE_KEYWORDS = [
  { pattern: 'passport', weight: 4 },
  { pattern: 'aadhaar', weight: 4 },
  { pattern: 'ssn', weight: 4 },
  { pattern: 'social[_ -]?security', weight: 4 },
  { pattern: 'medical', weight: 3 },
  { pattern: 'diagnosis', weight: 3 },
  { pattern: 'prescription', weight: 3 },
  { pattern: 'salary', weight: 3 },
  { pattern: 'payslip', weight: 3 },
  { pattern: 'bank[_ -]?statement', weight: 3 },
  { pattern: 'tax', weight: 2 },
  { pattern: 'confidential', weight: 3 },
  { pattern: 'secret', weight: 3 },
  { pattern: 'contract', weight: 2 },
  { pattern: 'agreement', weight: 2 },
  { pattern: 'resume|cv', weight: 1 },
];
export const MAX_KEYWORD_SCORE = 4;

// User-declared sensitivity dropdown, already collected in Upload.jsx since Phase 2/6.
export const MAX_USER_SENSITIVITY_SCORE = 3;

// Score-to-level thresholds, exactly as specified.
export const RISK_THRESHOLDS = [
  { level: 'CRITICAL', min: 9 },
  { level: 'HIGH', min: 7 },
  { level: 'MEDIUM', min: 4 },
  { level: 'LOW', min: 0 },
];