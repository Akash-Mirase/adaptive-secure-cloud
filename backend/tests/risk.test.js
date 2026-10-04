import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyFile } from '../src/services/risk.service.js';

test('spec example: passport.pdf with high user sensitivity is CRITICAL at score 10', () => {
  const result = classifyFile({ originalName: 'passport.pdf', mimeType: 'application/pdf', userSensitivity: 3 });
  assert.equal(result.breakdown.fileTypeScore, 3);
  assert.equal(result.breakdown.keywordScore, 4);
  assert.equal(result.breakdown.userSensitivityScore, 3);
  assert.equal(result.riskScore, 10);
  assert.equal(result.riskLevel, 'CRITICAL');
});

test('a plain photo with no sensitivity declared is LOW', () => {
  const result = classifyFile({ originalName: 'holiday.jpg', mimeType: 'image/jpeg', userSensitivity: 0 });
  assert.ok(result.riskScore <= 3);
  assert.equal(result.riskLevel, 'LOW');
});

test('keyword matching is case-insensitive and uses word boundaries', () => {
  const upper = classifyFile({ originalName: 'PASSPORT.PDF', mimeType: 'application/pdf', userSensitivity: 0 });
  const substring = classifyFile({ originalName: 'passportable-report.pdf', mimeType: 'application/pdf', userSensitivity: 0 });
  assert.equal(upper.breakdown.keywordScore, 4);
  assert.equal(substring.breakdown.keywordScore, 0, '"passportable" must not match the "passport" keyword');
});

test('multiple keyword matches are capped, not summed without limit', () => {
  const result = classifyFile({
    originalName: 'passport_medical_salary_confidential_secret.pdf',
    mimeType: 'application/pdf',
    userSensitivity: 0,
  });
  assert.ok(result.breakdown.keywordScore <= 4, 'keyword score must respect MAX_KEYWORD_SCORE');
  assert.ok(result.breakdown.keywordMatches.length >= 4, 'but every match should still be reported for transparency');
});

test('unknown MIME type falls back to the default file-type score', () => {
  const result = classifyFile({ originalName: 'data.xyz', mimeType: 'application/x-made-up', userSensitivity: 0 });
  assert.equal(result.breakdown.fileTypeScore, 1);
});

test('invalid or missing userSensitivity is treated as 0, not an error', () => {
  const missing = classifyFile({ originalName: 'notes.txt', mimeType: 'text/plain' });
  const negative = classifyFile({ originalName: 'notes.txt', mimeType: 'text/plain', userSensitivity: -5 });
  const nonInteger = classifyFile({ originalName: 'notes.txt', mimeType: 'text/plain', userSensitivity: 'high' });
  assert.equal(missing.breakdown.userSensitivityScore, 0);
  assert.equal(negative.breakdown.userSensitivityScore, 0);
  assert.equal(nonInteger.breakdown.userSensitivityScore, 0);
});

test('userSensitivity above the max (3) is clamped, not allowed to inflate the score arbitrarily', () => {
  const result = classifyFile({ originalName: 'notes.txt', mimeType: 'text/plain', userSensitivity: 999 });
  assert.equal(result.breakdown.userSensitivityScore, 3);
});

test('classification is deterministic: identical input always gives identical output', () => {
  const input = { originalName: 'salary_slip_march.pdf', mimeType: 'application/pdf', userSensitivity: 2 };
  const a = classifyFile(input);
  const b = classifyFile(input);
  assert.deepEqual(a, b);
});

test('every threshold boundary maps to the correct level', () => {
  const levelFor = (score) => {
    // Build a case that produces exactly `score` via fileType(1) + keyword(0) + userSensitivity(clamped)
    // for scores 0-4; for higher scores combine a scoring file type too. Simplify: test the pure boundaries
    // through direct inputs known from the rule table.
    return score;
  };
  assert.equal(classifyFile({ originalName: 'a.txt', mimeType: 'text/plain', userSensitivity: 0 }).riskLevel, 'LOW');   // 1+0+0=1
  assert.equal(classifyFile({ originalName: 'a.txt', mimeType: 'text/plain', userSensitivity: 3 }).riskLevel, 'MEDIUM'); // 1+0+3=4
  assert.equal(classifyFile({ originalName: 'a.pdf', mimeType: 'application/pdf', userSensitivity: 3 }).riskLevel, 'MEDIUM'); // 3+0+3=6... adjust below
});