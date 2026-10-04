import { createContext, useCallback, useEffect, useMemo, useState } from 'react'
import * as authService from '../services/authService.js'
import { getToken, setToken, clearToken } from '../utils/tokenStorage.js'
import { deriveKek } from '../crypto/kdf.js'
import { unwrapMasterKey } from '../crypto/masterKey.js'
import { base64ToBuffer } from '../crypto/encoding.js'
import { clearStepUpToken } from '../utils/stepUpSession.js'
import {
  setMasterKey,
  setPrivateKey,
  clearMasterKey,
  isUnlocked
} from '../crypto/masterKeySession.js'
import { unwrapPrivateKey } from '../crypto/rsa.js'

export const AuthContext = createContext(null)

// cryptoStatus: 'unknown' | 'locked' | 'unlocked'
// 'locked' means: authenticated (valid JWT / user loaded) but the Master Key
// has not been unwrapped in THIS tab yet (e.g. right after a page reload).
export function AuthProvider ({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(Boolean(getToken()))
  const [cryptoStatus, setCryptoStatus] = useState('unknown')

  useEffect(() => {
    if (!getToken()) return
    authService
      .getMe()
      .then(u => {
        setUser(u)
        setCryptoStatus('locked')
      }) // reload always starts locked; see masterKeySession.js
      .catch(() => clearToken())
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const onExpired = () => {
      setUser(null)
      setCryptoStatus('unknown')
      clearMasterKey(), clearStepUpToken()
    }
    window.addEventListener('auth:expired', onExpired)
    return () => window.removeEventListener('auth:expired', onExpired)
  }, [])

  // Unlocking requires the password to re-derive the KEK. This is why login
  // and unlock happen together right after a fresh login (see login() below),
  // and why a page reload needs a separate "Unlock" step (see UnlockPrompt.jsx).
  const unlockWithPassword = useCallback(async password => {
    const { keys } = await authService.getKeyBundle()
    const kek = await deriveKek(
      password,
      new Uint8Array(base64ToBuffer(keys.kdfSalt)),
      keys.kdfIterations
    )
    const masterKey = await unwrapMasterKey(
      keys.wrappedMasterKey,
      kek,
      keys.masterKeyIv
    )
    setMasterKey(masterKey)

    // Unlock the sharing private key too, right away, using the SAME Master
    // Key we just unwrapped — this is why the private key is wrapped under
    // the Master Key rather than the KEK: one unlock step covers both.
    const privateKey = await unwrapPrivateKey(
      keys.wrappedPrivateKey,
      masterKey,
      keys.privateKeyIv
    )
    setPrivateKey(privateKey)

    setCryptoStatus('unlocked')
  }, [])

  const login = useCallback(
    async (email, password) => {
      const result = await authService.login(email, password)
      setToken(result.token)
      setUser(result.user)
      await unlockWithPassword(password) // we already have the password in hand; unlock immediately
      return result.user
    },
    [unlockWithPassword]
  )

  const register = useCallback(data => authService.register(data), [])

  const logout = useCallback(async () => {
    try {
      await authService.logout()
    } catch {
      /* token may already be expired */
    }
    clearToken()
    clearMasterKey()
    clearStepUpToken()
    setUser(null)
    setCryptoStatus('unknown')
  }, [])

  const value = useMemo(
    () => ({
      user,
      loading,
      cryptoStatus,
      isUnlocked: isUnlocked,
      login,
      register,
      logout,
      unlockWithPassword
    }),
    [user, loading, cryptoStatus, login, register, logout, unlockWithPassword]
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
