import { useState, useEffect, useCallback, memo } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { useTranslation } from 'react-i18next'
import {
  Key, Activity, Plus, Server, BarChart3, Clock, Bot, Search, ShieldX, ArrowUpRight,
} from 'lucide-react'
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Line, LineChart } from 'recharts'
import { servicesApi, statsApi, systemApi, oauthApi } from '../services/api'
import useServiceWebSocket from '../hooks/useServiceWebSocket'
import LastChecked from '../components/LastChecked'
import {
  PageHeader, Button, Card, CardHeader, StatTile, StatusPill, StatusDot, Alert, EmptyState, LoadingBlock, Select,
  Table, THead, TBody, TR, TH, TD, SectionLabel, dotTones,
} from '../components/ui'

// recharts stroke attrs cannot read CSS vars: give fallback colors; the real line color
// follows the theme via index.css .chart-line-*
const CHART = { success: '#22C55E', failed: '#F87171' }

const ServiceHealthCard = memo(function ServiceHealthCard({ health, offlineServices, isLoading }) {
  const { t } = useTranslation()
  const healthItems = [
    { key: 'online', label: t('dashboard.serviceHealth.online'), tone: 'success' },
    { key: 'offline', label: t('dashboard.serviceHealth.offline'), tone: 'danger' },
    { key: 'error', label: t('dashboard.serviceHealth.error'), tone: 'warning' },
    { key: 'unknown', label: t('dashboard.serviceHealth.unknown'), tone: 'neutral' },
  ]
  return (
    <Card>
      <CardHeader
        title={t('dashboard.serviceHealth.title')}
        description={t(health.total === 1 ? 'dashboard.serviceHealth.registered' : 'dashboard.serviceHealth.registeredPlural', { n: health.total })}
        action={<Button variant="ghost" size="xs" to="/services">{t('dashboard.serviceHealth.viewAll')}</Button>}
      />
      {isLoading ? (
        <LoadingBlock className="py-6" size="sm" />
      ) : (
        <>
          {/* Stacked ratio bar + 2x2 legend: all four states are visible at a glance and labels are not truncated */}
          <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
            {health.total > 0 && healthItems.map(({ key, tone }) => (
              (health[key] || 0) > 0 && (
                <div key={key} className={dotTones[tone]} style={{ width: `${((health[key] || 0) / health.total) * 100}%` }} />
              )
            ))}
          </div>
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
            {healthItems.map(({ key, label, tone }) => (
              <div key={key} className="flex min-w-0 items-center justify-between gap-2 text-sm">
                <dt className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
                  <StatusDot tone={tone} className="h-1.5 w-1.5" />
                  <span className="truncate" title={label}>{label}</span>
                </dt>
                <dd className="shrink-0 font-medium tabular-nums text-foreground">{health[key] || 0}</dd>
              </div>
            ))}
          </dl>
          {offlineServices && offlineServices.length > 0 && (
            <div className="mt-4">
              <SectionLabel className="mb-2">{t('dashboard.serviceHealth.needAttention')}</SectionLabel>
              <Table bordered className="text-xs">
                <TBody>
                  {offlineServices.map((svc) => (
                    <TR key={svc.id || svc.name} className="h-9">
                      <TD className="h-9 py-0 pl-3 pr-2">
                        <span className="flex items-center gap-2">
                          <StatusDot tone={svc.status === 'error' ? 'warning' : 'danger'} />
                          {svc.id ? (
                            <Link to={`/services/${svc.id}`} title={t('dashboard.serviceHealth.openDetail')} className="truncate font-medium text-foreground hover:text-link">{svc.name}</Link>
                          ) : (
                            <span className="truncate font-medium text-foreground">{svc.name}</span>
                          )}
                        </span>
                      </TD>
                      <TD align="right" className="h-9 py-0 pl-2 pr-3 font-mono text-2xs text-muted-foreground">{svc.host}:{svc.port}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </div>
          )}
        </>
      )}
    </Card>
  )
})

const UsageSummaryCard = memo(function UsageSummaryCard({ summary, isLoading }) {
  const { t } = useTranslation()
  const items = [
    { label: t('dashboard.usage.allTime'), value: summary.total_all_time || 0 },
    { label: t('dashboard.usage.last7Days'), value: summary.total_7_days || 0 },
    { label: t('dashboard.usage.last24Hours'), value: summary.total_24_hours || 0 },
  ]
  return (
    <Card>
      <CardHeader title={t('dashboard.usage.title')} description={t('dashboard.usage.summary')} />
      {isLoading ? (
        <LoadingBlock className="py-6" size="sm" />
      ) : (
        <dl className="divide-y divide-border">
          {items.map(({ label, value }) => (
            <div key={label} className="flex items-center justify-between py-2.5">
              <dt className="text-sm text-muted-foreground">{label}</dt>
              <dd className="text-sm font-medium tabular-nums text-foreground">{value.toLocaleString()}</dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  )
})

const SystemStatusCard = memo(function SystemStatusCard({ scheduler, adminCount, issuer, kindData, isLoading }) {
  const { t } = useTranslation()
  const kindTotal = kindData.reduce((s, d) => s + d.value, 0)
  return (
    <Card>
      <CardHeader title={t('dashboard.system.title')} description={t('dashboard.system.overview')} />
      {isLoading ? (
        <LoadingBlock className="py-6" size="sm" />
      ) : (
        <>
          <dl className="divide-y divide-border">
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-sm text-muted-foreground">{t('dashboard.system.scheduler')}</dt>
              <dd>
                <StatusPill tone={scheduler?.is_running ? 'success' : 'danger'}>
                  {scheduler?.is_running ? t('dashboard.system.running') : t('dashboard.system.stopped')}
                </StatusPill>
              </dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-sm text-muted-foreground">{t('dashboard.system.scheduledJobs')}</dt>
              <dd className="text-sm font-medium tabular-nums text-foreground">{scheduler?.jobs_count || 0}</dd>
            </div>
            <div className="flex items-center justify-between py-2.5">
              <dt className="text-sm text-muted-foreground">{t('dashboard.system.admins')}</dt>
              <dd className="text-sm font-medium tabular-nums text-foreground">{adminCount || 0}</dd>
            </div>
            {issuer && (
              <div className="py-2.5">
                <dt className="text-sm text-muted-foreground">{t('dashboard.system.issuer')}</dt>
                <dd className="mt-1 break-all font-mono text-xs text-foreground">{issuer}</dd>
              </div>
            )}
          </dl>

          <div className="mt-4 border-t border-border pt-4">
            <SectionLabel className="mb-3">{t('dashboard.tokenKinds.title')}</SectionLabel>
            {kindData.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t('dashboard.tokenKinds.empty')}</p>
            ) : (
              <div className="space-y-2">
                {kindData.map((entry) => {
                  const pct = kindTotal ? (entry.value / kindTotal) * 100 : 0
                  return (
                    <div key={entry.name}>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">{entry.name}</span>
                        <span className="tabular-nums text-foreground">{entry.value} <span className="text-subtle-foreground">({pct.toFixed(0)}%)</span></span>
                      </div>
                      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                        <div className={clsx('h-full rounded-full', entry.accent ? 'bg-accent' : 'bg-subtle-foreground')} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </>
      )}
    </Card>
  )
})

const EVENT_ICON = { issued: Key, introspect: Search, revoked: ShieldX }

const ActivityRow = memo(function ActivityRow({ ev }) {
  const { t } = useTranslation()
  const Icon = EVENT_ICON[ev.event] || Activity
  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <div className="flex min-w-0 items-center gap-3">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-card text-muted-foreground">
          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-foreground">{t(`dashboard.activity.events.${ev.event}`, ev.event)}</p>
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            {ev.grant_type && <span className="shrink-0 rounded bg-muted px-1 text-2xs">{t(`dashboard.activity.grantTypes.${ev.grant_type}`, { defaultValue: ev.grant_type })}</span>}
            <span className="truncate">
              {ev.client_id || t('dashboard.activity.unknownClient')}{ev.audience ? ` → ${ev.audience}` : ''}{ev.ip ? ` · ${ev.ip}` : ''}
            </span>
          </p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <StatusDot tone={ev.success ? 'success' : 'danger'} className="h-1.5 w-1.5" />
        <LastChecked value={ev.at} withIcon={false} />
      </div>
    </div>
  )
})

const ChartTooltip = memo(function ChartTooltip({ active, payload, label }) {
  const { t } = useTranslation()
  if (!active || !payload || !payload.length) return null
  const success = payload.find((p) => p.dataKey === 'success')?.value || 0
  const failed = payload.find((p) => p.dataKey === 'failed')?.value || 0
  return (
    <div className="min-w-[10rem] rounded-md border border-border bg-popover p-3 text-xs shadow-overlay">
      <p className="mb-2 font-medium text-foreground">{label}</p>
      <div className="flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="success" />{t('dashboard.chart.success')}</span><span className="tabular-nums text-foreground">{success}</span></div>
      <div className="mt-1 flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="danger" />{t('dashboard.chart.failed')}</span><span className="tabular-nums text-foreground">{failed}</span></div>
      <div className="mt-2 flex items-center justify-between gap-4 border-t border-border pt-1.5"><span className="text-muted-foreground">{t('dashboard.chart.total')}</span><span className="tabular-nums font-medium text-foreground">{success + failed}</span></div>
    </div>
  )
})

const EMPTY_OVERVIEW = {
  service_health: { online: 0, offline: 0, error: 0, unknown: 0, total: 0 },
  offline_services: [],
  scheduler: { is_running: false, jobs_count: 0 },
  admin_count: 0,
  oauth: { clients: 0, pending_clients: 0, active_tokens: 0, active_pats: 0, issued_24h: 0 },
}

export default function DashboardPage() {
  const { t } = useTranslation()
  const [overview, setOverview] = useState(EMPTY_OVERVIEW)
  const [oauthOverview, setOauthOverview] = useState(null)
  const [usageSummary, setUsageSummary] = useState({ total_all_time: 0, total_7_days: 0, total_24_hours: 0 })
  const [usageStats, setUsageStats] = useState([])
  const [activity, setActivity] = useState([])
  const [servicesList, setServicesList] = useState([])
  const [selectedService, setSelectedService] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [isLoadingChart, setIsLoadingChart] = useState(false)
  const [error, setError] = useState(null)

  // WebSocket: real-time service health updates
  const handleHealthUpdate = useCallback((message) => {
    const svcName = message.service_name || message.service
    const svcStatus = message.data?.status || message.status
    if (!svcName || !svcStatus) return
    setOverview((prev) => {
      const newHealth = { ...prev.service_health }
      const oldStatus = message.data?.previous_status || message.old_status || 'unknown'
      if (oldStatus in newHealth && newHealth[oldStatus] > 0) newHealth[oldStatus]--
      if (svcStatus in newHealth) newHealth[svcStatus]++
      let offline = [...prev.offline_services]
      if (svcStatus === 'offline' || svcStatus === 'error') {
        if (!offline.find((s) => s.name === svcName)) {
          offline.push({ id: message.service_id, name: svcName, status: svcStatus, host: message.host || '', port: message.port || '' })
        }
      } else {
        offline = offline.filter((s) => s.name !== svcName)
      }
      return { ...prev, service_health: newHealth, offline_services: offline.slice(0, 5) }
    })
  }, [])

  const { isConnected: wsConnected } = useServiceWebSocket({ onHealthUpdate: handleHealthUpdate, enabled: true })

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      setIsLoading(true)
      setError(null)
      try {
        const [ov, oo, summary, daily, act, svcs] = await Promise.all([
          systemApi.getDashboardOverview().catch(() => null),
          oauthApi.overview().catch(() => null),
          statsApi.summary().catch(() => ({ total_all_time: 0, total_7_days: 0, total_24_hours: 0 })),
          statsApi.daily(7).catch(() => ({ stats: [] })),
          oauthApi.activity(8).catch(() => ({ events: [] })),
          servicesApi.getAll().catch(() => ({ services: [] })),
        ])
        if (cancelled) return
        if (ov) setOverview({ ...EMPTY_OVERVIEW, ...ov, oauth: { ...EMPTY_OVERVIEW.oauth, ...(ov.oauth || {}) } })
        setOauthOverview(oo)
        setUsageSummary(summary)
        setUsageStats(daily.stats || [])
        setActivity(act.events || [])
        setServicesList(svcs.services || [])
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load data')
      } finally {
        if (!cancelled) setIsLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  // Service filter changed -> reload charts
  useEffect(() => {
    if (isLoading) return
    let cancelled = false
    setIsLoadingChart(true)
    statsApi.daily(7, selectedService || null)
      .then((res) => { if (!cancelled) setUsageStats(res.stats || []) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setIsLoadingChart(false) })
    return () => { cancelled = true }
  }, [selectedService])   // eslint-disable-line react-hooks/exhaustive-deps

  const kindData = oauthOverview ? [
    { name: t('dashboard.tokenKinds.pat'), value: oauthOverview.active_pats || 0, accent: true },
    { name: t('dashboard.tokenKinds.access'), value: oauthOverview.active_access_tokens || 0 },
    { name: t('dashboard.tokenKinds.refresh'), value: oauthOverview.active_refresh_tokens || 0 },
  ].filter((d) => d.value > 0) : []
  const chartEmpty = usageStats.length === 0 || usageStats.every((s) => (s.success || 0) + (s.failed || 0) === 0)
  const selectedServiceName = servicesList.find((s) => s.id === selectedService)?.name

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('dashboard.title')}
        description={t('dashboard.subtitle')}
        meta={wsConnected && <StatusPill tone="success" pulse>{t('dashboard.live')}</StatusPill>}
        actions={
          <Button variant="primary" icon={Plus} to="/tokens/create">
            {t('dashboard.issueToken')}
          </Button>
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label={t('dashboard.stats.services')} value={overview.service_health.total} meta={t('dashboard.stats.onlineSuffix', { n: overview.service_health.online || 0 })} loading={isLoading} to="/services" />
        <StatTile label={t('dashboard.stats.clients')} value={overview.oauth.clients} meta={t('dashboard.stats.pendingSuffix', { n: overview.oauth.pending_clients || 0 })} loading={isLoading} to="/clients" />
        <StatTile label={t('dashboard.stats.activeTokens')} value={overview.oauth.active_tokens} meta={t('dashboard.stats.patsSuffix', { n: overview.oauth.active_pats || 0 })} loading={isLoading} to="/tokens" />
        <StatTile label={t('dashboard.stats.issued24h')} value={overview.oauth.issued_24h} meta={oauthOverview ? t('dashboard.stats.issued7dSuffix', { n: oauthOverview.issued_7d || 0 }) : undefined} loading={isLoading} />
      </div>

      {/* Pending clients notice */}
      {!isLoading && overview.oauth.pending_clients > 0 && (
        <Alert
          tone="warning"
          icon={Bot}
          title={t('dashboard.pendingClients.title', { n: overview.oauth.pending_clients })}
          action={<Button variant="secondary" size="sm" to="/clients">{t('dashboard.pendingClients.review')}</Button>}
        >
          {t('dashboard.pendingClients.hint')}
        </Alert>
      )}

      {/* Chart + recent activity */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title={<>{t('dashboard.chart.title')}{selectedServiceName && <span className="ml-2 font-normal text-muted-foreground">— {selectedServiceName}</span>}</>}
            description={t('dashboard.chart.subtitle')}
            action={
              <>
                <div className="hidden items-center gap-3 text-xs text-muted-foreground sm:flex">
                  <StatusPill tone="success">{t('dashboard.chart.success')}</StatusPill>
                  <StatusPill tone="danger">{t('dashboard.chart.failed')}</StatusPill>
                </div>
                <Select size="sm" value={selectedService} onChange={(e) => setSelectedService(e.target.value)} className="w-auto max-w-[200px]">
                  <option value="">{t('dashboard.chart.allServices')}</option>
                  {servicesList.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
                </Select>
              </>
            }
          />
          {isLoading || isLoadingChart ? (
            <LoadingBlock className="h-64 py-0" />
          ) : chartEmpty ? (
            <EmptyState className="h-64 py-0" icon={BarChart3} title={t('dashboard.chart.emptyTitle')} description={t('dashboard.chart.emptyHint')} />
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={usageStats} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid vertical={false} strokeDasharray="0" />
                  <XAxis dataKey="date" fontSize={11} tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => { const d = new Date(v); return isNaN(d) ? String(v) : `${d.getMonth() + 1}/${d.getDate()}` }} />
                  <YAxis fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} tickMargin={4} />
                  <Tooltip content={<ChartTooltip />} cursor={{ strokeWidth: 1 }} />
                  <Line className="chart-line-success" type="monotone" dataKey="success" stroke={CHART.success} strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-success' }} name={t('dashboard.chart.success')} />
                  <Line className="chart-line-failed" type="monotone" dataKey="failed" stroke={CHART.failed} strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-danger' }} name={t('dashboard.chart.failed')} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card>
          <CardHeader
            title={t('dashboard.activity.title')}
            description={t('dashboard.activity.subtitle')}
            action={<Button variant="ghost" size="xs" to="/audit">{t('dashboard.activity.viewAudit')}</Button>}
          />
          {isLoading ? (
            <div className="space-y-3">{[1, 2, 3].map((i) => <div key={i} className="skeleton h-10" />)}</div>
          ) : activity.length === 0 ? (
            <EmptyState
              compact
              icon={Clock}
              title={t('dashboard.activity.empty')}
              action={<Button variant="secondary" size="sm" icon={Plus} to="/tokens/create">{t('dashboard.activity.issueFirst')}</Button>}
            />
          ) : (
            <div className="divide-y divide-border">{activity.map((ev, i) => <ActivityRow key={`${ev.at}-${i}`} ev={ev} />)}</div>
          )}
        </Card>
      </div>

      {/* Health / usage / system */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ServiceHealthCard health={overview.service_health} offlineServices={overview.offline_services} isLoading={isLoading} />
        <UsageSummaryCard summary={usageSummary} isLoading={isLoading} />
        <SystemStatusCard scheduler={overview.scheduler} adminCount={overview.admin_count} issuer={oauthOverview?.issuer} kindData={kindData} isLoading={isLoading} />
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { to: '/tokens/create', icon: Plus, title: t('dashboard.quickActions.issueToken'), hint: t('dashboard.quickActions.issueTokenHint') },
          { to: '/tokens', icon: Key, title: t('dashboard.quickActions.manageTokens'), hint: t('dashboard.quickActions.manageTokensHint') },
          { to: '/clients', icon: Bot, title: t('dashboard.quickActions.clients'), hint: t('dashboard.quickActions.clientsHint') },
          { to: '/services', icon: Server, title: t('dashboard.quickActions.services'), hint: t('dashboard.quickActions.servicesHint') },
        ].map((a) => (
          <Card key={a.to} to={a.to} padding="sm" className="group flex items-center gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-muted-foreground">
              <a.icon className="h-4 w-4" aria-hidden="true" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-foreground">{a.title}</span>
              <span className="line-clamp-2 text-xs leading-snug text-muted-foreground">{a.hint}</span>
            </span>
            <ArrowUpRight className="h-4 w-4 shrink-0 text-subtle-foreground opacity-0 transition-opacity duration-200 group-hover:opacity-100" aria-hidden="true" />
          </Card>
        ))}
      </div>
    </div>
  )
}
