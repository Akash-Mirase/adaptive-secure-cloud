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
export async function requestStepUp(password) {
  const res = await api.post('/auth/step-up', { password });
  return res.data.data; // { stepUpToken, expiresAt }
}

export async function regenerateRecoveryKey(payload) {
  await api.post('/auth/recovery-key', payload);
}