// SINGLE SOURCE OF TRUTH for risk scoring (rule version 2).
// Change weights/lists here only; risk.service.js holds no hard-coded numbers.
export const RULE_VERSION = 2;

// ---- File type (MIME) ----
export const FILE_TYPE_SCORES = {
  'application/pdf': 3,
  'application/msword': 3,
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 3,
  'application/vnd.ms-excel': 3,
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 3,
  'application/zip': 2,
  'application/vnd.ms-powerpoint': 2,
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': 2,
  'image/png': 1, 'image/jpeg': 1, 'image/gif': 1, 'image/webp': 1,
  'text/plain': 1,
  'text/csv': 2,
};
export const DEFAULT_FILE_TYPE_SCORE = 1;
export const MAX_FILE_TYPE_SCORE = 3;

// Extension -> MIME. Used so a client cannot lower the type score by declaring a different MIME.
export const EXTENSION_MIME = {
  pdf: 'application/pdf', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  zip: 'application/zip', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
  gif: 'image/gif', webp: 'image/webp', txt: 'text/plain', csv: 'text/csv',
};

// ---- Metadata ----
export const METADATA_UNKNOWN_TYPE_POINTS = 1;   // neither MIME nor extension is recognised
export const METADATA_MISMATCH_POINTS = 1;       // declared MIME disagrees with the extension
export const METADATA_UNINSPECTED_POINTS = 1;    // inspection was expected but failed/partial/too large
export const MAX_METADATA_SCORE = 2;

// ---- Filename keywords (unchanged from rule version 1) ----
export const SENSITIVE_KEYWORDS = [
  { pattern: 'passport', weight: 4 }, { pattern: 'aadhaar', weight: 4 }, { pattern: 'ssn', weight: 4 },
  { pattern: 'social[_ -]?security', weight: 4 }, { pattern: 'medical', weight: 3 },
  { pattern: 'diagnosis', weight: 3 }, { pattern: 'prescription', weight: 3 },
  { pattern: 'salary', weight: 3 }, { pattern: 'payslip', weight: 3 },
  { pattern: 'bank[_ -]?statement', weight: 3 }, { pattern: 'tax', weight: 2 },
  { pattern: 'confidential', weight: 3 }, { pattern: 'secret', weight: 3 },
  { pattern: 'contract', weight: 2 }, { pattern: 'agreement', weight: 2 },
  { pattern: 'resume|cv', weight: 1 },
];
export const MAX_KEYWORD_SCORE = 4;

// ---- User-declared sensitivity: 0 Public, 1 Normal, 2 Personal, 3 Confidential, 4 Highly Confidential ----
export const MAX_USER_SENSITIVITY = 4;
export const SENSITIVITY_LABELS = ['Public', 'Normal', 'Personal', 'Confidential', 'Highly Confidential'];
// Security FLOOR: the final level can never be below this, whatever the scanners found.
export const SENSITIVITY_FLOOR = ['LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// ---- Content evidence (supplied by the browser; treated as untrusted, can only RAISE risk) ----
export const EVIDENCE_CATEGORIES = ['GOV_ID', 'FINANCIAL', 'HEALTH', 'CREDENTIAL', 'PERSONAL_CONTACT', 'BUSINESS'];
export const EVIDENCE_RULES = [
  'EMAIL', 'PHONE', 'AADHAAR', 'PAN', 'PASSPORT', 'CARD_NUMBER', 'IFSC', 'BANK_ACCOUNT',
  'FINANCIAL_TERMS', 'HEALTH_TERMS', 'PRIVATE_KEY', 'API_KEY', 'TOKEN', 'PASSWORD_ASSIGNMENT', 'BUSINESS_TERMS',
];
export const EVIDENCE_STRENGTHS = ['LOW', 'MEDIUM', 'HIGH'];
export const EVIDENCE_STATUSES = ['COMPLETE', 'PARTIAL', 'UNSUPPORTED', 'FAILED', 'TOO_LARGE'];
export const MAX_EVIDENCE_INDICATORS = 40;
export const MAX_EVIDENCE_COUNT = 100000;

// Points per CATEGORY (counted once per category: no stacking of several rules in one category).
export const CATEGORY_POINTS = {
  GOV_ID: 4, CREDENTIAL: 4, FINANCIAL: 3, HEALTH: 3, BUSINESS: 2, PERSONAL_CONTACT: 1,
};
export const LOW_STRENGTH_DIVISOR = 2;   // keyword-only evidence earns half points (rounded down)
export const COUNT_BONUS_THRESHOLD = 5;  // many occurrences in a category add one point
export const COUNT_BONUS_POINTS = 1;
export const MAX_CONTENT_SCORE = 6;
// Evidence FLOOR: a HIGH-strength hit from one of these rules sets a minimum level, because
// these are checksum- or marker-validated and are sensitive on their own. Evidence can only raise.
export const CONTENT_FLOOR_RULES = ['AADHAAR', 'PAN', 'PRIVATE_KEY', 'API_KEY', 'TOKEN', 'CARD_NUMBER'];
export const CONTENT_FLOOR_LEVEL = 'HIGH';

// ---- Context (anomaly signals) ----
export const CONTEXT_ACTIVE_ALERT_POINTS = 1;
export const MAX_CONTEXT_SCORE = 1;

export const RISK_THRESHOLDS = [
  { level: 'CRITICAL', min: 9 }, { level: 'HIGH', min: 7 },
  { level: 'MEDIUM', min: 4 }, { level: 'LOW', min: 0 },
];
export const LEVEL_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const MAX_RISK_SCORE = 20;
