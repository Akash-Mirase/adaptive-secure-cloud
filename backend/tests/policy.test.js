import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getPolicy } from '../src/config/securityPolicies.js';

test('LOW and MEDIUM require no step-up', () => {
  assert.equal(getPolicy('LOW').requiresStepUp, false);
  assert.equal(getPolicy('MEDIUM').requiresStepUp, false);
});

test('HIGH and CRITICAL require step-up; CRITICAL re-verifies more often than HIGH', () => {
  const high = getPolicy('HIGH');
  const critical = getPolicy('CRITICAL');
  assert.equal(high.requiresStepUp, true);
  assert.equal(critical.requiresStepUp, true);
  assert.ok(critical.stepUpValiditySeconds < high.stepUpValiditySeconds);
});

test('the sharing ceiling narrows as risk increases', () => {
  const order = { VIEW: 0, DOWNLOAD: 1, EDIT: 2, OWNER: 3 };
  const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const values = levels.map((l) => order[getPolicy(l).maxSharePermission]);
  for (let i = 1; i < values.length; i += 1) {
    assert.ok(values[i] <= values[i - 1], `${levels[i]} must not allow a wider share ceiling than ${levels[i - 1]}`);
  }
});

test('CRITICAL explicitly blocks public sharing', () => {
  assert.equal(getPolicy('CRITICAL').blockPublicSharing, true);
});

test('an unrecognized risk level falls back to a defined policy rather than throwing', () => {
  assert.deepEqual(getPolicy('NOT_A_LEVEL'), getPolicy('LOW'));
});