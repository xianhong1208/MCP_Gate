import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react'
import { sessionApi } from '../services/api'
import { useTranslation } from 'react-i18next'
import { useToast } from './ToastContext'
import { rememberRedirect } from '../utils/redirect'

const AuthContext = createContext(null)

const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000  // 30 minutes
const CHECK_INTERVAL_MS = 30 * 1000              // check every 30 seconds

/**
 * Single tenant: any logged-in user is the admin; there are no roles / permissions.
 * user shape: { id, email, username, auth_provider, has_password, is_active, created_at, last_login }
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const toast = useToast()
  const { t } = useTranslation()
  const lastActivityRef = useRef(Date.now())
  const idleTimeoutMsRef = useRef(DEFAULT_IDLE_TIMEOUT_MS)
  const isLoggingOutRef = useRef(false)

  const applyIdleTimeout = (minutes) => {
    if (minutes) idleTimeoutMsRef.current = minutes * 60 * 1000
  }

  // Force logout
  const forceLogout = useCallback(async () => {
    if (isLoggingOutRef.current) return
    isLoggingOutRef.current = true
    try { await sessionApi.logout() } catch {}
    setUser(null)
    setTimeout(() => { isLoggingOutRef.current = false }, 0)
  }, [])

  // Check the session on startup (cookie is sent automatically)
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const userData = await sessionApi.me()
        applyIdleTimeout(userData.idle_timeout_minutes)
        setUser(userData)
      } catch {
        setUser(null)
      } finally {
        setIsLoading(false)
      }
    }
    checkAuth()
  }, [])

  // Track user activity (for the idle timeout)
  useEffect(() => {
    const updateActivity = () => { lastActivityRef.current = Date.now() }
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart']
    events.forEach(event => window.addEventListener(event, updateActivity, { passive: true }))
    return () => {
      events.forEach(event => window.removeEventListener(event, updateActivity))
    }
  }, [])

  // Periodically check the idle timeout
  useEffect(() => {
    if (!user) return
    const interval = setInterval(() => {
      const idleMs = Date.now() - lastActivityRef.current
      if (idleTimeoutMsRef.current > 0 && idleMs >= idleTimeoutMsRef.current) {
        // Remember the current page to return to after re-login, and state the reason explicitly
        rememberRedirect(window.location.pathname + window.location.search)
        toast.info(t('auth.notices.idleLogout'), 8000)
        forceLogout()
      }
    }, CHECK_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [user, forceLogout, toast, t])

  // Listen for API 401 responses (session rejected by the backend)
  useEffect(() => {
    const handleAuthExpired = () => {
      if (!user) return
      rememberRedirect(window.location.pathname + window.location.search)
      toast.warning(t('auth.notices.sessionExpired'), 8000)
      forceLogout()
    }
    window.addEventListener('auth-expired', handleAuthExpired)
    return () => window.removeEventListener('auth-expired', handleAuthExpired)
  }, [user, forceLogout, toast, t])

  const login = useCallback(async (email, password) => {
    setError(null)
    try {
      const result = await sessionApi.login(email, password)
      applyIdleTimeout(result.idle_timeout_minutes)
      lastActivityRef.current = Date.now()
      setUser(result.user)
      return result
    } catch (err) {
      setError(err.message)
      throw err
    }
  }, [])

  /** First-run: create the owner account and log in on success */
  const setup = useCallback(async (email, password, username) => {
    setError(null)
    try {
      const result = await sessionApi.setup(email, password, username)
      applyIdleTimeout(result.idle_timeout_minutes)
      lastActivityRef.current = Date.now()
      setUser(result.user)
      return result
    } catch (err) {
      setError(err.message)
      throw err
    }
  }, [])

  const logout = useCallback(async () => {
    try { await sessionApi.logout() } catch {}
    setUser(null)
  }, [])

  // Reload the current user (e.g. after a rename)
  const refreshUser = useCallback(async () => {
    try {
      const userData = await sessionApi.me()
      setUser(userData)
      return userData
    } catch {
      setUser(null)
      return null
    }
  }, [])

  const value = {
    user,
    isLoading,
    error,
    isAuthenticated: !!user,
    login,
    setup,
    logout,
    refreshUser,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
