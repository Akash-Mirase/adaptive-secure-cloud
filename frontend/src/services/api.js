import axios from 'axios';
import { getToken, clearToken } from '../utils/tokenStorage.js';
import { getStepUpToken } from '../utils/stepUpSession.js';   // ← check this import exists

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000/api',
  timeout: 15000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  const stepUp = getStepUpToken();                              // ← check this
  if (stepUp) config.headers['X-Step-Up-Token'] = stepUp;       // ← and this
  return config;
});

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