// Sensitive-pattern detection. Runs ONLY in the browser, on text held in memory.
// It returns counts per rule, NEVER the matched values. Regex detection is heuristic:
// it has false positives and false negatives and cannot prove a file is safe.

// Verhoeff checksum: Aadhaar numbers carry one, which removes most random 12-digit false positives.
const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
export function verhoeffValid(num) {
  let c = 0;
  const digits = String(num).split('').reverse().map(Number);
  digits.forEach((d, i) => { c = D[c][P[i % 8][d]]; });
  return c === 0;
}
export function luhnValid(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i -= 1) {
    let n = Number(num[i]);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

const countMatches = (text, re, accept) => {
  let n = 0;
  for (const m of text.matchAll(re)) if (!accept || accept(m[0], m)) n += 1;
  return n;
};
const digitsOnly = (s) => s.replace(/[\s-]/g, '');

// Each rule: { rule, category, run(text) -> { count, strength } | null }
const RULES = [
  { rule: 'EMAIL', category: 'PERSONAL_CONTACT', run: (t) => {
    const n = countMatches(t, /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}\b/g);
    return n ? { count: n, strength: 'MEDIUM' } : null; } },
  { rule: 'PHONE', category: 'PERSONAL_CONTACT', run: (t) => {
    const n = countMatches(t, /(?<![\d.])(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\d.])/g);
    return n ? { count: n, strength: 'LOW' } : null; } },
  { rule: 'AADHAAR', category: 'GOV_ID', run: (t) => {
    const n = countMatches(t, /(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)/g, (s) => verhoeffValid(digitsOnly(s)));
    return n ? { count: n, strength: 'HIGH' } : null; } },
  { rule: 'PAN', category: 'GOV_ID', run: (t) => {
    const n = countMatches(t, /\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b/g);
    return n ? { count: n, strength: 'HIGH' } : null; } },
  // The passport format is easy to hit by accident, so the word "passport" must also appear.
  { rule: 'PASSPORT', category: 'GOV_ID', run: (t) => {
    if (!/\bpassport\b/i.test(t)) return null;
    const n = countMatches(t, /\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b/g);
    return n ? { count: n, strength: 'MEDIUM' } : null; } },
  { rule: 'CARD_NUMBER', category: 'FINANCIAL', run: (t) => {
    const n = countMatches(t, /(?<!\d)\d(?:[\s-]?\d){12,18}(?!\d)/g, (s) => { const d = digitsOnly(s); return d.length >= 13 && d.length <= 19 && luhnValid(d); });
    return n ? { count: n, strength: 'HIGH' } : null; } },
  { rule: 'IFSC', category: 'FINANCIAL', run: (t) => {
    const n = countMatches(t, /\b[A-Z]{4}0[A-Z0-9]{6}\b/g);
    return n ? { count: n, strength: 'MEDIUM' } : null; } },
  // Bare 9-18 digit numbers are everywhere; require an account-related word nearby.
  { rule: 'BANK_ACCOUNT', category: 'FINANCIAL', run: (t) => {
    const n = countMatches(t, /\b(?:a\/c|acc(?:ount)?)(?:\s*(?:no|number|num|#))?\.?\s*[:-]?\s*\d{9,18}\b/gi);
    return n ? { count: n, strength: 'MEDIUM' } : null; } },
  { rule: 'FINANCIAL_TERMS', category: 'FINANCIAL', run: (t) => {
    const n = countMatches(t, /\b(?:bank statement|account balance|net pay|gross salary|payslip|credit limit|swift code)\b/gi);
    return n ? { count: n, strength: 'LOW' } : null; } },
  { rule: 'HEALTH_TERMS', category: 'HEALTH', run: (t) => {
    const n = countMatches(t, /\b(?:diagnosis|diagnosed|prescription|patient|medical record|discharge summary|blood pressure|hiv|cancer|diabetes|\d{1,4}\s?mg)\b/gi);
    return n ? { count: n, strength: 'LOW' } : null; } },
  { rule: 'PRIVATE_KEY', category: 'CREDENTIAL', run: (t) => {
    const n = countMatches(t, /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g);
    return n ? { count: n, strength: 'HIGH' } : null; } },
  { rule: 'API_KEY', category: 'CREDENTIAL', run: (t) => {
    const n = countMatches(t, /\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z-]{10,})\b/g);
    return n ? { count: n, strength: 'HIGH' } : null; } },
  { rule: 'TOKEN', category: 'CREDENTIAL', run: (t) => {
    const n = countMatches(t, /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g);
    return n ? { count: n, strength: 'HIGH' } : null; } },
  { rule: 'PASSWORD_ASSIGNMENT', category: 'CREDENTIAL', run: (t) => {
    const n = countMatches(t, /\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S{6,}/gi);
    return n ? { count: n, strength: 'MEDIUM' } : null; } },
  { rule: 'BUSINESS_TERMS', category: 'BUSINESS', run: (t) => {
    const n = countMatches(t, /\b(?:strictly confidential|confidential|proprietary|internal use only|non-disclosure|nda|trade secret)\b/gi);
    return n ? { count: n, strength: 'LOW' } : null; } },
];

export function detectSensitivePatterns(text) {
  const indicators = [];
  if (typeof text !== 'string' || text.length === 0) return indicators;
  for (const { rule, category, run } of RULES) {
    const hit = run(text);
    if (hit) indicators.push({ category, rule, count: hit.count, strength: hit.strength });
  }
  return indicators;
}
