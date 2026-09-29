// The JWT lives in sessionStorage: it is cleared when the tab closes and is never sent
// automatically (unlike cookies), so there is no CSRF risk.
// TRADE-OFF: any XSS bug could read it. Mitigations: React escapes output, Helmet sets
// a strict Content-Security-Policy on the API, and tokens expire in 15 minutes.
// (With client-side encryption, XSS is dangerous regardless, because keys sit in browser memory.)
const KEY = 'asc_access_token';

export const getToken = () => {
  try { return sessionStorage.getItem(KEY); } catch { return null; }
};
export const setToken = (token) => {
  try { sessionStorage.setItem(KEY, token); } catch { /* storage blocked: session will not persist */ }
};
export const clearToken = () => {
  try { sessionStorage.removeItem(KEY); } catch { /* nothing to clear */ }
};