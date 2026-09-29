import { createContext, useCallback, useEffect, useMemo, useState } from 'react';
import * as authService from '../services/authService.js';
import { getToken, setToken, clearToken } from '../utils/tokenStorage.js';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  // If a token exists we must ask the server who we are before deciding what to render.
  const [loading, setLoading] = useState(Boolean(getToken()));

  useEffect(() => {
    if (!getToken()) return;
    authService
      .getMe()
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  // The Axios interceptor fires this event when the server rejects our token.
  useEffect(() => {
    const onExpired = () => setUser(null);
    window.addEventListener('auth:expired', onExpired);
    return () => window.removeEventListener('auth:expired', onExpired);
  }, []);

  const login = useCallback(async (email, password) => {
    const result = await authService.login(email, password);
    setToken(result.token);
    setUser(result.user);
    return result.user;
  }, []);

  const register = useCallback((data) => authService.register(data), []);

  const logout = useCallback(async () => {
    try {
      await authService.logout(); // revokes the token on the server
    } catch {
      /* token may already be expired; we still clear the local session */
    }
    clearToken();
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, loading, login, register, logout }), [user, loading, login, register, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}