import { useState, useEffect, useMemo } from 'react'
import { formatDateTime } from '../utils/format'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Check, Sparkles } from 'lucide-react'
import { oauthApi, servicesApi } from '../services/api'
import { useToast } from '../contexts/ToastContext'
import CodeBlock from '../components/CodeBlock'
import { describeScope } from '../utils/scopes'
import clsx from 'clsx'
import {
  PageHeader, Button, Badge, Card, CardHeader, Alert, Field, Input, Select, SectionLabel, DescriptionList,
} from '../components/ui'

const QUICK_DAYS = [7, 30, 90, 365]

/** Issue a Personal Access Token to paste into the MCP client's Authorization: Bearer. The plaintext is shown once. */
export default function CreateTokenPage() {
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()
  const toast = useToast()

  const [services, setServices] = useState([])
  const [scopes, setScopes] = useState([])
  const [isLoadingMeta, setIsLoadingMeta] = useState(true)
  const [serviceId, setServiceId] = useState(searchParams.get('service_id') || '')
  const [selectedScopes, setSelectedScopes] = useState(new Set())
  const [expiresDays, setExpiresDays] = useState(30)
  const [customDays, setCustomDays] = useState(false)
  const [label, setLabel] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([
      servicesApi.getAll().catch(() => ({ services: [] })),
      oauthApi.scopes.list().catch(() => ({ scopes: [] })),
    ]).then(([s, sc]) => {
      if (cancelled) return
      const list = s.services || []
      setServices(list)
      setScopes(sc.scopes || [])
      if (!serviceId && list.length === 1) setServiceId(list[0].id)
    }).finally(() => { if (!cancelled) setIsLoadingMeta(false) })
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const service = useMemo(() => services.find((s) => s.id === serviceId) || null, [services, serviceId])

  // Selectable scopes = registry scopes intersected with the service's allowed scopes (unrestricted -> all)
  const availableScopes = useMemo(() => {
    if (!service || !service.oauth_scopes || service.oauth_scopes.length === 0) return scopes
    const allowed = new Set(service.oauth_scopes)
    const known = scopes.filter((s) => allowed.has(s.name))
    // Also list scopes the service allows but the registry lacks, so the user can still see them
    const extra = service.oauth_scopes.filter((n) => !scopes.some((s) => s.name === n)).map((name) => ({ name, description: null, is_default: false }))
    return [...known, ...extra]
  }, [service, scopes])

  // Reset to the default scopes when the service changes
  useEffect(() => {
    setSelectedScopes(new Set(availableScopes.filter((s) => s.is_default).map((s) => s.name)))
  }, [availableScopes])

  const toggleScope = (name) => {
    setSelectedScopes((prev) => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!serviceId) return
    setError('')
    setIsLoading(true)
    try {
      const res = await oauthApi.tokens.createPersonal({
        serviceId,
        scopes: [...selectedScopes],
        expiresDays: Math.max(1, parseInt(expiresDays, 10) || 30),
        label: label.trim() || null,
      })
      setResult(res)
      toast.success(t('tokens.create.generateSuccess'))
      window.scrollTo({ top: 0, behavior: 'smooth' })
    } catch (err) {
      setError(err.message || t('tokens.create.generateFail'))
    } finally {
      setIsLoading(false)
    }
  }

  const resetForm = () => {
    setResult(null)
    setLabel('')
    setError('')
  }

  // ---------- Success screen ----------
  if (result) {
    const mcpUrl = service?.mcp_url || service?.effective_audience || '<your-mcp-server-url>'
    const name = service?.name || result.service_name || 'mcp-server'
    const claudeCmd = `claude mcp add --transport http ${name} ${mcpUrl} --header "Authorization: Bearer ${result.access_token}"`
    const mcpJson = { mcpServers: { [name]: { type: 'http', url: mcpUrl, headers: { Authorization: `Bearer ${result.access_token}` } } } }

    return (
      <div className="mx-auto max-w-3xl space-y-8">
        <PageHeader
          title={t('tokens.create.successTitle')}
          description={t('tokens.create.successSubtitle', { service: name })}
          backTo="/tokens"
          backLabel={t('tokens.create.backToTokens')}
          meta={
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-success/10 text-success">
              <Check className="h-3.5 w-3.5" aria-hidden="true" />
            </span>
          }
          actions={
            <>
              <Button variant="ghost" icon={Sparkles} onClick={resetForm}>{t('tokens.create.issueAnother')}</Button>
              <Button variant="ghost" to={`/tokens/${encodeURIComponent(result.jti)}`}>{t('tokens.create.viewToken')}</Button>
              <Button variant="secondary" to="/tokens">{t('tokens.create.viewAll')}</Button>
            </>
          }
        />

        <Card className="space-y-5">
          <Alert tone="warning" title={t('tokens.create.oneTimeTitle')}>
            {t('tokens.create.oneTimeBody')}
          </Alert>

          <CodeBlock title={t('tokens.create.tokenLabel')} value={result.access_token} sensitive copyLabel={t('tokens.create.copyToken')} />

          <DescriptionList
            className="rounded-md border border-border px-4"
            items={[
              { label: t('tokens.create.labelLabel'), value: result.label || '—' },
              { label: t('tokens.create.expiresAt'), value: formatDateTime(result.expires_at), mono: true },
              { label: t('tokens.create.scopesGranted'), value: (result.scopes || []).join(' ') || '—', mono: true },
            ]}
          />
        </Card>

        <Card className="space-y-4">
          <CardHeader title={t('tokens.create.snippetsTitle')} description={t('tokens.create.snippetsSubtitle')} className="mb-0" />
          <CodeBlock title={t('tokens.create.snippetClaude')} language="bash" value={claudeCmd} />
          <CodeBlock title={t('tokens.create.snippetMcpJson')} language="json" value={mcpJson} />
        </Card>
      </div>
    )
  }

  // ---------- Form ----------
  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <PageHeader
        title={t('tokens.create.title')}
        description={t('tokens.create.subtitle')}
        backTo="/tokens"
        backLabel={t('tokens.create.backToTokens')}
      />

      <form onSubmit={handleSubmit}>
        <Card className="space-y-6">
          {error && <Alert tone="danger">{error}</Alert>}

          {/* Service */}
          <section className="space-y-4">
            <div>
              <SectionLabel>{t('tokens.create.serviceLabel')}</SectionLabel>
              <p className="mt-1 text-xs text-muted-foreground">{t('tokens.create.serviceHint')}</p>
            </div>
            {isLoadingMeta ? (
              <div className="skeleton h-9" />
            ) : services.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t('tokens.create.noServices')}{' '}
                <Link to="/services" className="text-link transition-colors duration-200 hover:text-link-hover">{t('tokens.create.registerService')}</Link>
              </p>
            ) : (
              <Select value={serviceId} onChange={(e) => setServiceId(e.target.value)} required>
                <option value="">{t('tokens.create.selectService')}</option>
                {services.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}{s.mcp_url ? ` — ${s.mcp_url}` : ''}</option>
                ))}
              </Select>
            )}
            {service && (
              <DescriptionList
                className="rounded-md border border-border px-4"
                items={[
                  { label: t('tokens.create.audience'), value: service.effective_audience || '—', mono: true },
                  { label: t('tokens.create.mcpUrl'), value: service.mcp_url || '—', mono: true },
                ]}
              />
            )}
          </section>

          {/* Scopes */}
          <section className="space-y-4 border-t border-border pt-6">
            <div>
              <SectionLabel>{t('tokens.create.scopesLabel')}</SectionLabel>
              <p className="mt-1 text-xs text-muted-foreground">
                {service?.oauth_scopes?.length ? t('tokens.create.restrictedHint') : t('tokens.create.scopesHint')}
              </p>
            </div>
            {availableScopes.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('tokens.create.noScopes')}</p>
            ) : (
              <div className="divide-y divide-border rounded-md border border-border">
                {availableScopes.map((s) => {
                  const checked = selectedScopes.has(s.name)
                  return (
                    <label
                      key={s.name}
                      className={clsx(
                        'flex cursor-pointer items-start gap-3 px-4 py-3 transition-colors duration-200',
                        checked ? 'bg-primary-soft/60' : 'hover:bg-muted/60',
                      )}
                    >
                      <input type="checkbox" className="ui-checkbox mt-0.5" checked={checked} onChange={() => toggleScope(s.name)} />
                      <span className="min-w-0">
                        <span className="flex items-center gap-2 font-mono text-sm font-medium text-foreground">
                          {s.name}
                          {s.is_default && <Badge tone="success">{t('tokens.create.defaultTag')}</Badge>}
                        </span>
                        {describeScope(t, s.name, s.description) && <span className="mt-0.5 block text-xs text-muted-foreground">{describeScope(t, s.name, s.description)}</span>}
                      </span>
                    </label>
                  )
                })}
              </div>
            )}
          </section>

          {/* Expiry + label */}
          <section className="grid gap-5 border-t border-border pt-6">
            <Field label={t('tokens.create.expiresLabel')}>
              <div className="flex flex-wrap items-center gap-2">
                {QUICK_DAYS.map((d) => {
                  const active = !customDays && expiresDays === d
                  return (
                    <Button
                      key={d}
                      type="button"
                      size="sm"
                      variant={active ? 'soft' : 'secondary'}
                      onClick={() => { setExpiresDays(d); setCustomDays(false) }}
                      aria-pressed={active}
                    >
                      {t('tokens.create.days', { n: d })}
                    </Button>
                  )
                })}
                <Button
                  type="button"
                  size="sm"
                  variant={customDays ? 'soft' : 'secondary'}
                  onClick={() => setCustomDays(true)}
                  aria-pressed={customDays}
                >
                  {t('tokens.create.customDays')}
                </Button>
                {customDays && (
                  <Input
                    type="number"
                    size="sm"
                    min={1}
                    max={3650}
                    value={expiresDays}
                    onChange={(e) => setExpiresDays(e.target.value)}
                    className="w-24"
                    autoFocus
                  />
                )}
              </div>
            </Field>

            <Field label={t('tokens.create.labelLabel')}>
              <Input
                type="text"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                maxLength={128}
                placeholder={t('tokens.create.labelPlaceholder')}
              />
            </Field>
          </section>

          <div className="-mx-5 -mb-5 flex items-center justify-between gap-3 border-t border-border px-5 py-3">
            <p className="text-xs text-subtle-foreground">{t('tokens.create.footerHint')}</p>
            <div className="flex shrink-0 items-center gap-2">
              <Button variant="secondary" to="/tokens">{t('tokens.create.cancel')}</Button>
              <Button type="submit" variant="primary" icon={Sparkles} loading={isLoading} disabled={!serviceId}>
                {isLoading ? t('tokens.create.submitting') : t('tokens.create.submit')}
              </Button>
            </div>
          </div>
        </Card>
      </form>
    </div>
  )
}
