import api from './api.js';

// Forwards the ENTIRE payload (name, email, password, plus the full client-
// generated key bundle: kdfSalt, kdfIterations, wrappedMasterKey, masterKeyIv,
// recoveryWrappedMasterKey, recoveryIv, recoveryKey). Do not destructure this
// down to a few fields — the backend's registration validator requires the
// complete key hierarchy created in Register.jsx.
export async function register(payload) {
  const res = await api.post('/auth/register', payload);
  return res.data.data.user;
}

export async function login(email, password) {
  const res = await api.post('/auth/login', { email, password });
  return res.data.data; // { user, token, expiresAt }
}

export async function getMe() {
  const res = await api.get('/auth/me');
  return res.data.data.user;
}

export async function logout() {
  await api.post('/auth/logout');
}

export async function getKeyBundle() {
  const res = await api.get('/auth/keys');
  return res.data.data; // { keys: {...} }
}

export async function getRecoveryBundle(email) {
  const res = await api.get('/auth/recovery-bundle', { params: { email } });
  return res.data.data; // { recoveryWrappedMasterKey, recoveryIv }
}

export async function recoverAccount(payload) {
  await api.post('/auth/recover', payload);
}

export async function regenerateRecoveryKey(payload) {
  await api.post('/auth/recovery-key', payload);
}

export async function completeMfaLogin(mfaToken, secondFactor) {
  const res = await api.post('/auth/login/mfa', { mfaToken, ...secondFactor });
  return res.data.data; // { user, token, expiresAt }
}
export async function requestStepUp(password, extra = {}) { // replaces the existing requestStepUp
  const res = await api.post('/auth/step-up', { password, ...extra });
  return res.data.data;
}
export async function logoutAll() {
  await api.post('/auth/logout-all');
}
export const getMfaStatus = async () => (await api.get('/mfa/status')).data.data;
export const beginMfaEnrollment = async (password) => (await api.post('/mfa/enroll', { password })).data.data;
export const confirmMfaEnrollment = async (code) => (await api.post('/mfa/enroll/confirm', { code })).data.data;
export const disableMfa = async (payload) => { await api.post('/mfa/disable', payload); };
export const regenerateMfaCodes = async (payload) => (await api.post('/mfa/recovery-codes', payload)).data.data;