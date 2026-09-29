import axios from 'axios';
import { getToken, clearToken } from '../utils/tokenStorage.js';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000/api',
  timeout: 15000,
});

// Attach the JWT to every request.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// If the server says our session is invalid or expired, drop it and tell the app.
// Login and register 401/409 errors are normal user errors, so they are excluded.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = error.config?.url || '';
    const isAuthAttempt = url.startsWith('/auth/login') || url.startsWith('/auth/register');
    if (error.response?.status === 401 && !isAuthAttempt) {
      clearToken();
      window.dispatchEvent(new Event('auth:expired'));
    }
    return Promise.reject(error);
  }
);

export default api;