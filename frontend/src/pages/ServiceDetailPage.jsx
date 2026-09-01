import { useState, useEffect, useCallback } from 'react'
import { formatDateTime, formatDate } from '../utils/format'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Copy, Check, Trash2, Clock, RefreshCw, ChevronDown, ChevronUp,
  Activity, Key, Edit3, Wrench, Terminal, FileJson, Code2,
} from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { servicesApi, statsApi, oauthApi } from '../services/api'
import LastChecked from '../components/LastChecked'
import CodeBlock from '../components/CodeBlock'
import ServiceFormModal from '../components/ServiceFormModal'
import HealthIndicator from '../components/HealthIndicator'
import { copyToClipboard } from '../utils/clipboard'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import { KindBadge, StatusBadge, ScopeChips } from './TokensPage'
import clsx from 'clsx'
import {
  PageHeader, Button, IconButton, Badge, StatusPill, StatusDot, Card, CardHeader, SectionLabel, DescriptionList,
  EmptyState, Alert, LoadingBlock, Tabs, SegmentedControl,
} from '../components/ui'

// recharts stroke attrs cannot read CSS vars: give fallback colors; the real line color
// follows the theme via index.css .chart-line-*
const CHART = { success: '#22C55E', failed: '#F87171' }

function CustomTooltip({ active, payload, label }) {
  const { t } = useTranslation()
  if (!active || !payload || !payload.length) return null
  const success = payload.find((p) => p.dataKey === 'success')?.value || 0
  const failed = payload.find((p) => p.dataKey === 'failed')?.value || 0
  return (
    <div className="min-w-[10rem] rounded-md border border-border bg-popover p-3 text-xs shadow-overlay">
      <p className="mb-2 font-medium text-foreground">{label}</p>
      <div className="flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="success" />{t('services.detail.chartSuccess')}</span><span className="tabular-nums text-foreground">{success}</span></div>
      <div className="mt-1 flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="danger" />{t('services.detail.chartFailed')}</span><span className="tabular-nums text-foreground">{failed}</span></div>
      <div className="mt-2 flex items-center justify-between gap-4 border-t border-border pt-1.5"><span className="text-muted-foreground">{t('services.detail.totalLabel')}</span><span className="tabular-nums font-medium text-foreground">{success + failed}</span></div>
    </div>
  )
}

function ToolItem({ tool }) {
  const { t } = useTranslation()
  const [isExpanded, setIsExpanded] = useState(false)
  const toast = useToast()
  const handleCopySchema = async () => {
    try {
      await copyToClipboard(JSON.stringify(tool.input_schema, null, 2))
      toast.success(t('services.common.schemaCopied'))
    } catch {
      toast.error(t('services.common.schemaCopyFailed'))
    }
  }
  return (
    <div className="py-3">
      <div className="flex items-start justify-between gap-2">
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex min-w-0 flex-1 items-start gap-2 text-left"
          aria-expanded={isExpanded}
        >
          {isExpanded
            ? <ChevronUp className="mt-0.5 h-4 w-4 shrink-0 text-subtle-foreground" aria-hidden="true" />
            : <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-subtle-foreground" aria-hidden="true" />}
          <span className="min-w-0">
            <span className="block truncate font-mono text-xs font-medium text-foreground">{tool.name}</span>
            {tool.description && <span className="mt-0.5 block text-xs text-muted-foreground">{tool.description}</span>}
          </span>
        </button>
        {tool.input_schema && (
          <IconButton size="sm" icon={Copy} onClick={handleCopySchema} title={t('services.common.copyInputSchema')} />
        )}
      </div>
      {isExpanded && tool.input_schema && (
        <div className="ml-6 mt-2">
          <p className="mb-1.5 text-xs text-muted-foreground">{t('services.common.inputSchema')}</p>
          <pre className="overflow-x-auto rounded-md border border-border bg-muted/50 p-3 font-mono text-xs text-foreground">{JSON.stringify(tool.input_schema, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}

/** Turn a raw health-check exception into a short, translated label; the raw text stays in the tooltip. */
function describeHealthError(t, raw) {
  const text = String(raw || '')
  if (/timed? ?out/i.test(text)) return t('services.health.timeout')
  if (/cannot connect|connection (refused|failed|reset)|connect call failed|unreachable|name resolution/i.test(text)) return t('services.health.unreachable')
  return t('services.health.failed')
}

// Integration snippets are grouped by target (family) and flavour (variant); the backend key is `${family}_${variant}`.
const SNIPPET_FAMILIES = [
  { key: 'claude_code', labelKey: 'services.detail.snippetFamily.claudeCode', icon: Terminal, lang: 'bash', variants: ['oauth', 'pat'] },
  { key: 'mcp_json', labelKey: 'services.detail.snippetFamily.mcpJson', icon: FileJson, lang: 'json', variants: ['oauth', 'pat'] },
  { key: 'fastmcp', labelKey: 'services.detail.snippetFamily.fastmcp', icon: Code2, lang: 'python', variants: ['server', 'client'] },
]

export default function ServiceDetailPage() {
  const { t } = useTranslation()
  const { serviceId } = useParams()
  const navigate = useNavigate()
  const { confirmDelete, confirmRevoke } = useConfirm()
  const toast = useToast()
  const decodedServiceId = decodeURIComponent(serviceId)

  const [service, setService] = useState(null)
  const [scopes, setScopes] = useState([])
  const [snippets, setSnippets] = useState(null)
  const [snippetFamily, setSnippetFamily] = useState('claude_code')
  const [snippetVariant, setSnippetVariant] = useState('oauth')
  const [tokens, setTokens] = useState([])
  const [usageStats, setUsageStats] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [isLoadingStats, setIsLoadingStats] = useState(true)
  const [error, setError] = useState(null)
  const [copiedEndpoint, setCopiedEndpoint] = useState(false)
  const [isCheckingHealth, setIsCheckingHealth] = useState(false)
  const [isRefreshingTools, setIsRefreshingTools] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [revokingJti, setRevokingJti] = useState(null)

  const reload = useCallback(async () => {
    const updated = await servicesApi.getById(decodedServiceId, true)
    setService(updated)
    return updated
  }, [decodedServiceId])

  useEffect(() => {
    let cancelled = false
    setIsLoading(true)
    setError(null)
    Promise.all([
      servicesApi.getById(decodedServiceId, true),
      oauthApi.scopes.list().catch(() => ({ scopes: [] })),
      oauthApi.snippets(decodedServiceId).catch(() => null),
      oauthApi.tokens.list({ serviceId: decodedServiceId }).catch(() => ({ tokens: [] })),
    ]).then(([svc, sc, sn, tk]) => {
      if (cancelled) return
      setService(svc)
      setScopes(sc.scopes || [])
      setSnippets(sn)
      setTokens(tk.tokens || [])
    }).catch((err) => {
      if (!cancelled) setError(err.message || t('services.detail.loadFailed'))
    }).finally(() => { if (!cancelled) setIsLoading(false) })
    return () => { cancelled = true }
  }, [decodedServiceId, t])

  useEffect(() => {
    if (!service) return
    let cancelled = false
    setIsLoadingStats(true)
    statsApi.daily(30, service.id)
      .then((res) => { if (!cancelled) setUsageStats(res.stats || []) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setIsLoadingStats(false) })
    return () => { cancelled = true }
  }, [service?.id])   // eslint-disable-line react-hooks/exhaustive-deps

  const handleCopy = async (text) => {
    try {
      await copyToClipboard(text)
      setCopiedEndpoint(true)
      toast.success(t('services.common.endpointCopied'))
      setTimeout(() => setCopiedEndpoint(false), 2000)
    } catch {
      toast.error(t('services.common.endpointCopyFailed'))
    }
  }

  const handleCheckHealth = async () => {
    setIsCheckingHealth(true)
    try {
      const result = await servicesApi.checkHealth(decodedServiceId)
      toast.success(t('services.detail.healthCheckResult', { status: result.status }))
      await reload()
    } catch (err) {
      toast.error(t('services.detail.healthCheckFailed', { message: err.message }))
    } finally {
      setIsCheckingHealth(false)
    }
  }

  const handleRefreshTools = async () => {
    setIsRefreshingTools(true)
    try {
      const result = await servicesApi.refreshTools(decodedServiceId)
      toast.success(t('services.detail.refreshToolsSuccess', { n: result.tools_count }))
      await reload()
    } catch (err) {
      toast.error(t('services.detail.refreshToolsFailed', { message: err.message }))
    } finally {
      setIsRefreshingTools(false)
    }
  }

  const handleUpdate = async (fields) => {
    await servicesApi.update(decodedServiceId, fields)
    await reload()
    oauthApi.snippets(decodedServiceId).then(setSnippets).catch(() => {})
    toast.success(t('services.detail.updateSuccess'))
  }

  const handleDelete = async () => {
    if (!service) return
    const confirmed = await confirmDelete(t('services.detail.deleteConfirmTarget', { name: service.name }))
    if (!confirmed) return
    try {
      await servicesApi.delete(decodedServiceId)
      toast.success(t('services.detail.deleteSuccess', { name: service.name }))
      navigate('/services')
    } catch (err) {
      toast.error(t('services.detail.deleteFailed', { message: err.message }))
    }
  }

  const handleRevokeToken = async (tk) => {
    const ok = await confirmRevoke(tk.label ? `"${tk.label}"` : `${tk.kind} ${tk.jti.slice(0, 8)}…`)
    if (!ok) return
    setRevokingJti(tk.jti)
    try {
      await oauthApi.tokens.revoke(tk.jti)
      toast.success(t('tokens.list.revokeSuccess'))
      const res = await oauthApi.tokens.list({ serviceId: decodedServiceId })
      setTokens(res.tokens || [])
    } catch (err) {
      toast.error(t('tokens.list.revokeFail', { message: err.message }))
    } finally {
      setRevokingJti(null)
    }
  }

  if (isLoading) {
    return <LoadingBlock className="min-h-[400px]" />
  }

  if (error || !service) {
    return (
      <div className="space-y-8">
        <PageHeader
          title={t('services.detail.subtitleType')}
          backTo="/services"
          backLabel={t('services.detail.backToServices')}
        />
        <Alert tone="danger">{error || t('services.detail.loadFailed')}</Alert>
      </div>
    )
  }

  const totalSuccess = usageStats.reduce((s, x) => s + (x.success || 0), 0)
  const totalFailed = usageStats.reduce((s, x) => s + (x.failed || 0), 0)
  const totalUsage = totalSuccess + totalFailed
  const hasMcpConnection = !!(service.host && service.port)
  const activeFamily = SNIPPET_FAMILIES.find((f) => f.key === snippetFamily) || SNIPPET_FAMILIES[0]
  const activeVariant = activeFamily.variants.includes(snippetVariant) ? snippetVariant : activeFamily.variants[0]
  const activeSnippetKey = `${activeFamily.key}_${activeVariant}`
  const activeSnippetTitle = `${t(activeFamily.labelKey)} · ${t(`services.detail.snippetVariant.${activeVariant}`)}`
  const selectFamily = (key) => {
    const family = SNIPPET_FAMILIES.find((f) => f.key === key) || SNIPPET_FAMILIES[0]
    setSnippetFamily(family.key)
    if (!family.variants.includes(snippetVariant)) setSnippetVariant(family.variants[0])
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title={service.name}
        description={service.description || t('services.common.noDescription')}
        backTo="/services"
        backLabel={t('services.detail.backToServices')}
        meta={
          <>
            {service.health && <HealthIndicator status={service.health.status} />}
            {service.source === 'auto_discovered' && <Badge tone="warning">{t('services.detail.autoTag')}</Badge>}
            {service.source === 'managed' && <Badge tone="accent">{t('services.list.managedTag')}</Badge>}
          </>
        }
        actions={
          <>
            {hasMcpConnection && (
              <IconButton
                variant="secondary"
                icon={isCheckingHealth ? RefreshCw : Activity}
                title={t('services.detail.healthCheck')}
                onClick={handleCheckHealth}
                disabled={isCheckingHealth}
                className={clsx(isCheckingHealth && 'animate-spin')}
              />
            )}
            <Button variant="secondary" icon={Edit3} onClick={() => setShowEditModal(true)}>
              {t('services.detail.edit')}
            </Button>
            <Button variant="primary" icon={Key} to={`/tokens/create?service_id=${encodeURIComponent(service.id)}`}>
              {t('services.detail.issuePat')}
            </Button>
            <Button variant="destructive" icon={Trash2} onClick={handleDelete}>
              {t('services.detail.delete')}
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Left column */}
        <div className="space-y-4 lg:col-span-2">
          {/* Connection */}
          <Card>
            <CardHeader
              title={t('services.common.mcpConnection')}
              action={service.mcp_url && (
                <Button variant="ghost" size="xs" icon={copiedEndpoint ? Check : Copy} onClick={() => handleCopy(service.mcp_url)}>
                  {copiedEndpoint ? t('services.detail.copied') : t('services.detail.copy')}
                </Button>
              )}
            />
            <DescriptionList
              items={[
                { label: t('services.detail.mcpUrl'), value: service.mcp_url || t('services.tools.noConnection'), mono: !!service.mcp_url },
                { label: t('services.detail.hostLabel'), value: service.host || '—', mono: !!service.host },
                { label: t('services.detail.portLabel'), value: service.port || '—', mono: !!service.port },
                { label: t('services.detail.protocolLabel'), value: (service.protocol || 'http').toUpperCase(), mono: true },
                { label: t('services.detail.mcpPathLabel'), value: service.mcp_path || '/mcp', mono: true },
                {
                  label: t('services.detail.audienceLabel'),
                  value: (
                    <span>
                      <span className="block break-all font-mono text-xs">{service.effective_audience || '—'}</span>
                      <span className="mt-1 block text-xs font-sans text-muted-foreground">
                        {service.oauth_audience ? t('services.detail.audienceCustom') : t('services.detail.audienceDefault')}
                      </span>
                    </span>
                  ),
                },
                {
                  label: t('services.detail.authRequired'),
                  value: service.requires_auth ? t('services.detail.yes') : t('services.detail.no'),
                },
              ]}
            />
            {(service.has_static_token || service.health?.response_time_ms != null || service.health?.last_checked || service.created_at || service.health?.error_message) && (
            <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-4 text-xs text-muted-foreground">
              {service.has_static_token && (
                <Badge tone="neutral"><Key className="h-3 w-3" />{t('services.detail.staticTokenBadge')}</Badge>
              )}
              {service.health?.response_time_ms != null && (
                <span className="flex items-center gap-1.5">
                  <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('services.detail.responseTime')}
                  <span className="font-mono tabular-nums text-foreground">{Math.round(service.health.response_time_ms)}ms</span>
                </span>
              )}
              {service.health?.last_checked && (
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('services.detail.lastChecked')}
                  <LastChecked value={service.health.last_checked} withIcon={false} className="text-foreground" />
                </span>
              )}
              {service.created_at && (
                <span className="tabular-nums">{t('services.detail.createdAt', { date: formatDate(service.created_at) })}</span>
              )}
              {service.health?.error_message && (
                <span className="max-w-full truncate text-danger" title={service.health.error_message}>{describeHealthError(t, service.health.error_message)}</span>
              )}
            </div>
            )}
          </Card>

          {/* Usage */}
          <Card>
            <CardHeader
              title={t('services.detail.usageHistoryTitle')}
              description={t('services.detail.usageHistorySubtitle')}
              action={
                <dl className="flex items-center divide-x divide-border text-xs">
                  <div className="pr-4"><dt className="text-muted-foreground">{t('services.detail.totalLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalUsage}</dd></div>
                  <div className="px-4"><dt className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="success" />{t('services.detail.successLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalSuccess}</dd></div>
                  <div className="pl-4"><dt className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="danger" />{t('services.detail.failedLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalFailed}</dd></div>
                </dl>
              }
            />
            {isLoadingStats ? (
              <LoadingBlock className="h-64 py-0" />
            ) : totalUsage === 0 ? (
              <EmptyState className="h-64 py-0" icon={Clock} title={t('services.detail.noUsageTitle')} description={t('services.detail.noUsageHint')} />
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={usageStats} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                    <CartesianGrid vertical={false} strokeDasharray="0" />
                    <XAxis dataKey="date" fontSize={11} tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => { const d = new Date(v); return `${d.getMonth() + 1}/${d.getDate()}` }} />
                    <YAxis fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} tickMargin={4} />
                    <Tooltip content={<CustomTooltip />} cursor={{ strokeWidth: 1 }} />
                    <Area className="chart-line-success" type="monotone" dataKey="success" stroke={CHART.success} strokeWidth={2} fill={CHART.success} fillOpacity={0.08} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-success' }} name={t('services.detail.chartSuccess')} />
                    <Area className="chart-line-failed" type="monotone" dataKey="failed" stroke={CHART.failed} strokeWidth={2} fill={CHART.failed} fillOpacity={0.08} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-danger' }} name={t('services.detail.chartFailed')} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>

          {/* Integration */}
          <Card>
            <CardHeader
              title={t('services.detail.integrationTitle')}
              description={t('services.detail.integrationSubtitle')}
            />
            {!snippets ? (
              <p className="text-sm text-muted-foreground">{t('services.detail.snippetsUnavailable')}</p>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <Tabs
                    size="sm"
                    value={activeFamily.key}
                    onChange={selectFamily}
                    className="min-w-0 flex-1"
                    items={SNIPPET_FAMILIES.map((f) => ({ key: f.key, label: t(f.labelKey), icon: f.icon }))}
                  />
                  <SegmentedControl
                    size="sm"
                    value={activeVariant}
                    onChange={setSnippetVariant}
                    items={activeFamily.variants.map((v) => ({ key: v, label: t(`services.detail.snippetVariant.${v}`) }))}
                  />
                </div>
                <CodeBlock title={activeSnippetTitle} language={activeFamily.lang} value={snippets[activeSnippetKey]} rows={22} />
                <DescriptionList
                  items={[
                    { label: t('services.detail.issuerLabel'), value: snippets.issuer, mono: true },
                    { label: t('services.detail.audienceLabel'), value: snippets.audience, mono: true },
                  ]}
                />
              </div>
            )}
          </Card>
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Scopes + tags */}
          <Card>
            <SectionLabel className="mb-2">{t('services.detail.scopesTitle')}</SectionLabel>
            {service.oauth_scopes && service.oauth_scopes.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {service.oauth_scopes.map((s) => (
                  <Badge key={s} tone="accent" mono title={scopes.find((x) => x.name === s)?.description || ''}>{s}</Badge>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">{t('services.detail.scopesAll')}</p>
            )}
            <SectionLabel className="mb-2 mt-5">{t('services.detail.tagsTitle')}</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {(service.tags || []).map((tag) => <Badge key={tag} tone="neutral">{tag}</Badge>)}
              {(!service.tags || service.tags.length === 0) && <span className="text-xs text-muted-foreground">{t('services.detail.noTags')}</span>}
            </div>
          </Card>

          {/* Tools */}
          <Card>
            <CardHeader
              title={t('services.detail.mcpToolsTitle', { n: service.tools?.length || 0 })}
              action={hasMcpConnection && (
                <Button variant="ghost" size="xs" icon={RefreshCw} onClick={handleRefreshTools} loading={isRefreshingTools}>
                  {t('services.detail.refreshFromServer')}
                </Button>
              )}
            />
            {(service.tools || []).length === 0 ? (
              <EmptyState
                compact
                icon={Wrench}
                title={t('services.detail.noToolsFound')}
                description={hasMcpConnection ? t('services.common.refreshServerHint') : undefined}
              />
            ) : (
              <div className="divide-y divide-border">
                {service.tools.map((tool) => <ToolItem key={tool.id || tool.name} tool={tool} />)}
              </div>
            )}
          </Card>

          {/* Active tokens for this service */}
          <Card>
            <CardHeader
              title={t('services.detail.tokensTitle', { n: tokens.length })}
              action={<Button variant="ghost" size="xs" to={`/tokens?service_id=${encodeURIComponent(service.id)}`}>{t('services.detail.viewAllTokens')}</Button>}
            />
            {tokens.length === 0 ? (
              <EmptyState compact icon={Key} title={t('services.detail.tokensEmpty')} description={t('services.detail.tokensHint')} />
            ) : (
              <div className="divide-y divide-border">
                {tokens.slice(0, 10).map((tk) => (
                  <div key={tk.jti} className="group flex items-center justify-between gap-2 py-2.5">
                    <Link to={`/tokens/${encodeURIComponent(tk.jti)}`} className="flex min-w-0 flex-1 items-center gap-2">
                      <KindBadge kind={tk.kind} />
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium text-foreground transition-colors duration-200 group-hover:text-link">{tk.label || tk.client_name || tk.jti}</span>
                        <span className="block truncate text-xs text-muted-foreground">{tk.client_name || tk.client_id}{tk.expires_at ? ` · ${t('services.detail.tokenExpires')} ${formatDateTime(tk.expires_at)}` : ''}</span>
                      </span>
                    </Link>
                    <div className="hidden 2xl:block"><ScopeChips scopes={tk.scopes} max={2} /></div>
                    <StatusBadge status={tk.status} />
                    <IconButton
                      variant="destructive"
                      icon={revokingJti === tk.jti ? RefreshCw : Trash2}
                      onClick={() => handleRevokeToken(tk)}
                      disabled={revokingJti === tk.jti}
                      title={t('tokens.list.revokeTitle')}
                      className={clsx(revokingJti === tk.jti && 'animate-spin')}
                    />
                  </div>
                ))}
                {tokens.length > 10 && <p className="pt-2 text-center text-xs text-muted-foreground tabular-nums">+{tokens.length - 10}</p>}
              </div>
            )}
          </Card>
        </div>
      </div>

      {showEditModal && (
        <ServiceFormModal mode="edit" service={service} scopes={scopes} onClose={() => setShowEditModal(false)} onSubmit={handleUpdate} />
      )}
    </div>
  )
}
