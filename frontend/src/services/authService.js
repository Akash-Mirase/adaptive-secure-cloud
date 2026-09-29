import api from './api.js';

export async function register({ name, email, password }) {
  const res = await api.post('/auth/register', { name, email, password });
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