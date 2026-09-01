import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../contexts/AuthContext'
import { sessionApi } from '../services/api'
import { Eye, EyeOff } from 'lucide-react'
import AuthShell from '../components/AuthShell'
import { Button, IconButton, Input, Field, Alert, Spinner } from '../components/ui'

/** First run: create the owner account. Afterwards always redirects to /login. */
export default function SetupPage() {
  const { t } = useTranslation()
  const { setup } = useAuth()
  const navigate = useNavigate()

  const [checking, setChecking] = useState(true)
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    sessionApi.status()
      .then((s) => {
        if (cancelled) return
        if (!s.needs_setup) navigate('/login', { replace: true })
        else setChecking(false)
      })
      .catch(() => { if (!cancelled) setChecking(false) })
    return () => { cancelled = true }
  }, [navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    if (password !== confirmPassword) {
      setError(t('auth.errors.passwordMismatch'))
      return
    }
    if (password.length < 8) {
      setError(t('auth.errors.passwordTooShort'))
      return
    }
    setIsLoading(true)
    try {
      await setup(email, password, username)
      navigate('/', { replace: true })
    } catch (err) {
      if (err.code === 'auth.setup_already_done') {
        navigate('/login', { replace: true })
        return
      }
      setError(err.message || t('auth.setup.failed'))
    } finally {
      setIsLoading(false)
    }
  }

  if (checking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-subtle-foreground">
        <Spinner size="lg" />
      </div>
    )
  }

  const mismatch = !!confirmPassword && password !== confirmPassword

  return (
    <AuthShell maxWidth="max-w-md">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-foreground">{t('auth.setup.title')}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t('auth.setup.subtitle')}</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert tone="danger">{error}</Alert>}

        <Field label={t('auth.setup.email')} htmlFor="setup-email">
          <Input
            id="setup-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
            autoFocus
          />
        </Field>

        <Field label={t('auth.setup.username')} htmlFor="setup-username">
          <Input
            id="setup-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="nickname"
            maxLength={64}
            placeholder={t('auth.setup.usernamePlaceholder')}
          />
        </Field>

        <Field label={t('auth.setup.password')} htmlFor="setup-password" help={t('auth.setup.passwordHint')}>
          <div className="relative">
            <Input
              id="setup-password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="pr-10"
              autoComplete="new-password"
              minLength={8}
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

        <Field
          label={t('auth.setup.confirmPassword')}
          htmlFor="setup-confirm"
          error={mismatch ? t('auth.errors.passwordMismatch') : undefined}
        >
          <Input
            id="setup-confirm"
            type={showPassword ? 'text' : 'password'}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            invalid={mismatch}
            autoComplete="new-password"
            required
          />
        </Field>

        <Button type="submit" variant="primary" className="w-full" loading={isLoading}>
          {isLoading ? t('auth.setup.submitting') : t('auth.setup.submit')}
        </Button>
      </form>
    </AuthShell>
  )
}
