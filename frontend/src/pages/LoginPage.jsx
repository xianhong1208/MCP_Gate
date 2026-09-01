import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import i18n from '../i18n'
import { useAuth } from '../contexts/AuthContext'
import { sessionApi } from '../services/api'
import { consumeRedirect, peekRedirect } from '../utils/redirect'
import { Eye, EyeOff, Globe } from 'lucide-react'
import AuthShell from '../components/AuthShell'
import { Button, IconButton, Input, Field, Alert, DividerWithText } from '../components/ui'

/** Monochrome provider icons (currentColor, no brand colors) */
function GithubIcon({ className }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden="true">
      <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56v-2.17c-3.2.7-3.87-1.37-3.87-1.37-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.25 5.66.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z" />
    </svg>
  )
}

function GoogleIcon({ className }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden="true">
      <path d="M21.6 12.23c0-.68-.06-1.33-.17-1.96H12v3.7h5.38a4.6 4.6 0 0 1-2 3.02v2.5h3.24c1.9-1.75 2.98-4.32 2.98-7.26Z" />
      <path d="M12 21.6c2.7 0 4.97-.9 6.62-2.42l-3.24-2.5c-.9.6-2.04.95-3.38.95-2.6 0-4.8-1.75-5.59-4.11H3.07v2.58A10 10 0 0 0 12 21.6Z" />
      <path d="M6.41 13.52A6 6 0 0 1 6.1 11.6c0-.67.11-1.31.31-1.92V7.1H3.07a10 10 0 0 0 0 9l3.34-2.58Z" />
      <path d="M12 5.58c1.47 0 2.79.5 3.83 1.5l2.87-2.87A10 10 0 0 0 3.07 7.1l3.34 2.58C7.2 7.33 9.4 5.58 12 5.58Z" />
    </svg>
  )
}

const providerIcons = { github: GithubIcon, google: GoogleIcon }

function describeLoginError(code) {
  if (!code) return ''
  if (i18n.exists(`errors.${code}`)) return i18n.t(`errors.${code}`)
  return i18n.t('auth.errors.loginFailed', { code })
}

export default function LoginPage() {
  const { t } = useTranslation()
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(() => describeLoginError(searchParams.get('error')))
  const [providers, setProviders] = useState(null)   // null = not loaded yet

  // Already logged in: send the user straight back to where they were going (e.g. /consent?rid=...)
  useEffect(() => {
    if (!authLoading && isAuthenticated) navigate(consumeRedirect(), { replace: true })
  }, [authLoading, isAuthenticated, navigate])

  // First run -> setup page; also fetch the available login methods
  useEffect(() => {
    let cancelled = false
    sessionApi.status()
      .then((s) => {
        if (cancelled) return
        if (s.needs_setup) {
          navigate('/setup', { replace: true })
          return
        }
        setProviders(s.providers || [])
      })
      .catch(() => { if (!cancelled) setProviders([]) })
    return () => { cancelled = true }
  }, [navigate])

  const oauthProviders = (providers || []).filter((p) => p.kind === 'oauth')
  // Show the password form before providers load, to avoid a flash
  const localEnabled = providers === null || providers.some((p) => p.kind === 'password')
  const nextPath = peekRedirect()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      await login(email, password)
      navigate(consumeRedirect())
    } catch (err) {
      setError(err.message || t('auth.errors.invalidCredentials'))
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <AuthShell>
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-foreground">{t('auth.login.title')}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t('auth.login.subtitle')}</p>
      </div>

      {error && <Alert tone="danger" className="mb-5">{error}</Alert>}

      {localEnabled ? (
        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label={t('auth.login.email')} htmlFor="login-email">
            <Input
              id="login-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
              autoFocus
            />
          </Field>

          <Field label={t('auth.login.password')} htmlFor="login-password">
            <div className="relative">
              <Input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pr-10"
                autoComplete="current-password"
                required
              />
              <IconButton
                size="sm"
                icon={showPassword ? EyeOff : Eye}
                title={showPassword ? 'Hide' : 'Show'}
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-1 top-1/2 -translate-y-1/2"
              />
            </div>
          </Field>

          <Button type="submit" variant="primary" className="w-full" loading={isLoading}>
            {isLoading ? t('auth.login.loggingIn') : t('auth.login.submit')}
          </Button>
        </form>
      ) : (
        <p className="text-sm text-muted-foreground">
          {oauthProviders.length > 0 ? t('auth.login.localDisabled') : t('auth.login.noProviders')}
        </p>
      )}

      {oauthProviders.length > 0 && (
        <>
          {localEnabled && (
            <DividerWithText className="my-6">{t('auth.login.orContinueWith')}</DividerWithText>
          )}
          <div className="space-y-2">
            {oauthProviders.map((p) => {
              const Icon = providerIcons[p.name] || Globe
              return (
                <Button
                  key={p.name}
                  href={sessionApi.oauthStartUrl(p.name, nextPath)}
                  variant="secondary"
                  icon={Icon}
                  className="w-full"
                >
                  {t('auth.login.continueWith', { name: p.display_name || p.name })}
                </Button>
              )
            })}
          </div>
        </>
      )}
    </AuthShell>
  )
}
