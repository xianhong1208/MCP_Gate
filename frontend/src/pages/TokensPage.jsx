import { formatDateTime } from '../utils/format'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Key, Plus, Search, RefreshCw, Ban, Eye, Download, ChevronLeft, ChevronRight,
} from 'lucide-react'
import { oauthApi, servicesApi } from '../services/api'
import { exportTokensToCSV } from '../utils/export'
import { usePreferences } from '../contexts/PreferencesContext'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import LastChecked from '../components/LastChecked'
import clsx from 'clsx'
import {
  PageHeader, Button, IconButton, Badge, StatusPill, Card, Alert, EmptyState, LoadingBlock,
  SearchInput, Select, Checkbox,
  Table, THead, TBody, TR, TH, TD, RowActions,
} from '../components/ui'

// kind / status → Badge / StatusPill tone
export const KIND_BADGE = {
  pat: 'accent',
  access: 'info',
  refresh: 'neutral',
}
export const STATUS_BADGE = {
  active: 'success',
  expired: 'warning',
  revoked: 'neutral',
}

export function KindBadge({ kind }) {
  const { t } = useTranslation()
  return <Badge tone={KIND_BADGE[kind] || KIND_BADGE.refresh}>{t(`tokens.kind.${kind}`, kind)}</Badge>
}

export function StatusBadge({ status }) {
  const { t } = useTranslation()
  return <StatusPill tone={STATUS_BADGE[status] || STATUS_BADGE.revoked}>{t(`tokens.status.${status}`, status)}</StatusPill>
}

export function ScopeChips({ scopes, max = 3 }) {
  const { t } = useTranslation()
  if (!scopes || scopes.length === 0) return <span className="text-xs text-subtle-foreground">{t('tokens.common.noScopes')}</span>
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.slice(0, max).map((s) => (
        <Badge key={s} tone="neutral" mono>{s}</Badge>
      ))}
      {scopes.length > max && <span className="text-xs text-muted-foreground tabular-nums">+{scopes.length - max}</span>}
    </div>
  )
}

export default function TokensPage() {
  const { t } = useTranslation()
  const { preferences } = usePreferences()
  const { confirmRevoke } = useConfirm()
  const toast = useToast()

  const [tokens, setTokens] = useState([])
  const [services, setServices] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [includeInactive, setIncludeInactive] = useState(false)
  const [page, setPage] = useState(1)
  const [revoking, setRevoking] = useState(null)
  const pageSize = preferences.pageSize || 20

  const loadData = useCallback(async ({ silent = false } = {}) => {
    if (!silent) {
      setIsLoading(true)
      setError(null)
    }
    try {
      const [tokensRes, servicesRes] = await Promise.all([
        oauthApi.tokens.list({ kind: kind || undefined, serviceId: serviceId || undefined, includeInactive, limit: 1000 }),
        servicesApi.getAll().catch(() => ({ services: [] })),
      ])
      setTokens(tokensRes.tokens || [])
      setServices(servicesRes.services || [])
    } catch (err) {
      setError(err.message || t('tokens.list.loadFail'))
    } finally {
      if (!silent) setIsLoading(false)
    }
  }, [kind, serviceId, includeInactive, t])

  useEffect(() => { loadData() }, [loadData])
  useEffect(() => { setPage(1) }, [search, kind, serviceId, includeInactive])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return tokens
    return tokens.filter((tk) =>
      tk.jti?.toLowerCase().includes(q) ||
      tk.label?.toLowerCase().includes(q) ||
      tk.client_name?.toLowerCase().includes(q) ||
      tk.client_id?.toLowerCase().includes(q) ||
      tk.service_name?.toLowerCase().includes(q) ||
      tk.audience?.toLowerCase().includes(q) ||
      tk.sub?.toLowerCase().includes(q) ||
      (tk.scopes || []).some((s) => s.toLowerCase().includes(q)))
  }, [tokens, search])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize)

  const handleRevoke = async (tk) => {
    const confirmed = await confirmRevoke(tk.label ? `"${tk.label}"` : `${tk.kind} ${tk.jti.slice(0, 8)}…`)
    if (!confirmed) return
    setRevoking(tk.jti)
    try {
      await oauthApi.tokens.revoke(tk.jti)
      toast.success(t('tokens.list.revokeSuccess'))
      await loadData({ silent: true })
    } catch (err) {
      toast.error(t('tokens.list.revokeFail', { message: err.message }))
    } finally {
      setRevoking(null)
    }
  }

  const hasFilters = !!(search || kind || serviceId)

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('tokens.list.title')}
        description={t('tokens.list.subtitle')}
        actions={
          <>
            <IconButton
              variant="secondary"
              icon={RefreshCw}
              title={t('tokens.list.refresh')}
              onClick={() => loadData()}
              disabled={isLoading}
              className={clsx(isLoading && 'animate-spin')}
            />
            {filtered.length > 0 && (
              <IconButton variant="secondary" icon={Download} title={t('tokens.list.exportTitle')} onClick={() => exportTokensToCSV(filtered)} />
            )}
            <Button variant="primary" icon={Plus} to="/tokens/create">
              {t('tokens.list.issue')}
            </Button>
          </>
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          icon={Search}
          size="sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t('tokens.list.searchPlaceholder')}
          className="min-w-[220px] flex-1"
        />
        <Select size="sm" value={kind} onChange={(e) => setKind(e.target.value)} className="w-auto">
          <option value="">{t('tokens.list.allKinds')}</option>
          <option value="pat">{t('tokens.kind.pat')}</option>
          <option value="access">{t('tokens.kind.access')}</option>
          <option value="refresh">{t('tokens.kind.refresh')}</option>
        </Select>
        <Select size="sm" value={serviceId} onChange={(e) => setServiceId(e.target.value)} className="w-auto max-w-[220px]">
          <option value="">{t('tokens.list.allServices')}</option>
          {services.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </Select>
        <label className="flex cursor-pointer items-center gap-2 whitespace-nowrap text-sm text-muted-foreground">
          <Checkbox checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} />
          {t('tokens.list.includeInactive')}
        </label>
      </div>

      {/* Table */}
      {isLoading ? (
        <LoadingBlock />
      ) : filtered.length === 0 ? (
        <Card padding="none">
          <EmptyState
            icon={Key}
            title={t('tokens.list.empty')}
            description={hasFilters ? t('tokens.list.adjustFilters') : t('tokens.list.emptyHint')}
            action={!hasFilters && (
              <Button variant="soft" icon={Plus} to="/tokens/create">{t('tokens.list.issue')}</Button>
            )}
          />
        </Card>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          <Table bordered={false}>
            <THead>
              <TR hover={false} group={false}>
                <TH>{t('tokens.list.colToken')}</TH>
                <TH>{t('tokens.list.colClient')}</TH>
                <TH>{t('tokens.list.colService')}</TH>
                <TH className="hidden 2xl:table-cell">{t('tokens.list.colScopes')}</TH>
                <TH className="hidden 2xl:table-cell">{t('tokens.list.colIssued')}</TH>
                <TH>{t('tokens.list.colExpires')}</TH>
                <TH className="hidden 2xl:table-cell">{t('tokens.list.colLastUsed')}</TH>
                <TH>{t('tokens.list.colStatus')}</TH>
                <TH align="right" className="w-20"><span className="sr-only">{t('tokens.list.colActions')}</span></TH>
              </TR>
            </THead>
            <TBody>
              {pageItems.map((tk) => (
                <TR key={tk.jti}>
                  <TD className="max-w-[240px]">
                    <Link to={`/tokens/${encodeURIComponent(tk.jti)}`} className="block min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate font-medium text-foreground transition-colors duration-200 hover:text-link">
                          {tk.label || <span className="text-subtle-foreground">{t('tokens.list.noLabel')}</span>}
                        </span>
                        <KindBadge kind={tk.kind} />
                      </div>
                      <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={tk.jti}>{tk.jti}</p>
                    </Link>
                  </TD>
                  <TD className="max-w-[180px]">
                    <span className="block truncate text-foreground" title={tk.client_id}>{tk.client_name || tk.client_id}</span>
                  </TD>
                  <TD className="max-w-[220px]">
                    {tk.service_id ? (
                      <Link to={`/services/${encodeURIComponent(tk.service_id)}`} className="block truncate text-foreground transition-colors duration-200 hover:text-link">
                        {tk.service_name || tk.service_id}
                      </Link>
                    ) : (
                      <span className="text-subtle-foreground">—</span>
                    )}
                    {tk.audience && (
                      <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={tk.audience}>{tk.audience}</p>
                    )}
                  </TD>
                  <TD className="hidden 2xl:table-cell"><ScopeChips scopes={tk.scopes} max={2} /></TD>
                  <TD className="hidden whitespace-nowrap 2xl:table-cell" muted>{tk.issued_at ? formatDateTime(tk.issued_at) : '—'}</TD>
                  <TD className="whitespace-nowrap" muted>{tk.expires_at ? formatDateTime(tk.expires_at) : t('tokens.common.never')}</TD>
                  <TD className="hidden whitespace-nowrap 2xl:table-cell" muted>
                    {tk.last_used_at ? <LastChecked value={tk.last_used_at} /> : <span className="text-xs text-subtle-foreground">{t('tokens.common.neverUsed')}</span>}
                  </TD>
                  <TD><StatusBadge status={tk.status} /></TD>
                  <TD align="right">
                    <RowActions>
                      <IconButton icon={Eye} title={t('tokens.list.viewDetails')} to={`/tokens/${encodeURIComponent(tk.jti)}`} />
                      {tk.status === 'active' && (
                        <IconButton
                          variant="destructive"
                          icon={revoking === tk.jti ? RefreshCw : Ban}
                          title={t('tokens.list.revokeTitle')}
                          onClick={() => handleRevoke(tk)}
                          disabled={revoking === tk.jti}
                          className={clsx(revoking === tk.jti && 'animate-spin')}
                        />
                      )}
                    </RowActions>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>

          <div className="flex h-12 items-center justify-between border-t border-border px-4 text-xs text-muted-foreground">
            <span className="tabular-nums">
              {t('tokens.list.pagination', {
                from: (page - 1) * pageSize + 1,
                to: Math.min(page * pageSize, filtered.length),
                total: filtered.length,
              })}
            </span>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" icon={ChevronLeft} onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} aria-label={t('common.pagination.previous')} />
              <span className="tabular-nums">{t('tokens.list.pageOf', { page, total: totalPages })}</span>
              <Button variant="secondary" size="sm" icon={ChevronRight} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} aria-label={t('common.pagination.next')} />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
