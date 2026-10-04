import api from './api.js';

export async function lookupUser(email) {
  const res = await api.get('/users/lookup', { params: { email } });
  return res.data.data.user; // { id, name, email, publicKey }
}