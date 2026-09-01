import { useState, useEffect, useRef } from 'react'
import { formatDateTime } from '../utils/format'
import { useTranslation } from 'react-i18next'
import {
  FileText,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  User,
  Server,
  Key,
  Bot,
  Shield,
  Download,
  ChevronDown,
} from 'lucide-react'
import { auditApi } from '../services/api'
import { exportAuditLogsToCSV } from '../utils/export'
import { useToast } from '../contexts/ToastContext'
import clsx from 'clsx'
import {
  PageHeader, Button, IconButton, StatusPill, Card, EmptyState, Alert, LoadingBlock,
  Field, Input, Select, Table, THead, TBody, TR, TH, TD, Dialog, DialogBody, SectionLabel,
} from '../components/ui'
import CodeBlock from '../components/CodeBlock'

const ACTION_KEYS = [
  'token_issue',
  'token_revoke',
  'oauth_client_create',
  'oauth_client_approve',
  'oauth_client_revoke',
  'oauth_client_delete',
  'oauth_key_rotate',
  'create_service',
  'delete_service',
  'update_service',
  'refresh_tools',
  'scan_services',
  'admin_setup',
  'admin_login',
  'admin_logout',
  'admin_update',
  'cleanup_expired',
  'rate_limit_exceeded',
]

const resourceTypeIcons = {
  token: Key,
  oauth_client: Bot,
  service: Server,
  admin: User,
  system: Shield,
}

const statusConfig = {
  success: { tone: 'success', text: 'text-success' },
  failure: { tone: 'danger', text: 'text-danger' },
  error: { tone: 'warning', text: 'text-warning' },
}

export default function AuditLogPage() {
  const { t } = useTranslation()
  const toast = useToast()

  // Translated action label for an action key, falling back to raw value
  const getActionLabel = (action) => {
    if (!action) return ''
    const key = `audit.actions.${action}`
    const translated = t(key)
    return translated === key ? action : translated
  }

  // Translated resource type label, falling back to raw value
  const getResourceTypeLabel = (resourceType) => {
    if (!resourceType) return ''
    const key = `audit.resourceType.${resourceType}`
    const translated = t(key)
    return translated === key ? resourceType : translated
  }

  // Translated status label, falling back to raw value
  const getStatusLabel = (status) => {
    if (!status) return ''
    const key = `audit.status.${status}`
    const translated = t(key)
    return translated === key ? status : translated
  }
  const [logs, setLogs] = useState([])
  const [totalCount, setTotalCount] = useState(0)
  const [isLoading, setIsLoading] = useState(true)

  const [isExporting, setIsExporting] = useState(false)
  const [showExportMenu, setShowExportMenu] = useState(false)
  const exportMenuRef = useRef(null)
  const [error, setError] = useState(null)

  // Close export menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target)) {
        setShowExportMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Filters
  const [filters, setFilters] = useState({
    action: '',
    resourceType: '',
    actorName: '',
    status: '',
  })
  const [showFilters, setShowFilters] = useState(false)

  // Pagination
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)

  // Selected log detail
  const [selectedLog, setSelectedLog] = useState(null)

  // `requestId` guards against out-of-order responses when filters change quickly
  const requestId = useRef(0)
  const loadLogs = async () => {
    const id = ++requestId.current
    setIsLoading(true)
    setError(null)
    try {
      const res = await auditApi.getLogs({
        action: filters.action || undefined,
        resourceType: filters.resourceType || undefined,
        actorName: filters.actorName || undefined,
        status: filters.status || undefined,
        page,
        pageSize,
      })
      if (id !== requestId.current) return
      setLogs(res.logs || [])
      setTotalCount(res.total_count || 0)
    } catch (err) {
      if (id !== requestId.current) return
      console.error('Failed to load audit logs:', err)
      setError(err.message || t('audit.toast.loadFailed'))
    } finally {
      if (id === requestId.current) setIsLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [page, filters])

  const totalPages = Math.ceil(totalCount / pageSize)

  const clearFilters = () => {
    setFilters({ action: '', resourceType: '', actorName: '', status: '' })
    setPage(1)
  }

  const hasActiveFilters = Object.values(filters).some(Boolean)


  const handleExport = async (limit) => {
    setShowExportMenu(false)
    setIsExporting(true)
    try {
      const res = await auditApi.getLogs({
        action: filters.action || undefined,
        resourceType: filters.resourceType || undefined,
        actorName: filters.actorName || undefined,
        status: filters.status || undefined,
        page: 1,
        pageSize: limit,
      })
      const allLogs = res.logs || []
      if (allLogs.length === 0) {
        toast.warning(t('audit.toast.noLogs'))
        return
      }
      exportAuditLogsToCSV(allLogs)
      toast.success(t('audit.toast.exported', { n: allLogs.length }))
    } catch (err) {
      console.error('Failed to export audit logs:', err)
      toast.error(t('audit.toast.exportFailed'))
    } finally {
      setIsExporting(false)
    }
  }

  const detailItems = selectedLog ? [
    { label: t('audit.detail.action'), value: getActionLabel(selectedLog.action) },
    { label: t('audit.detail.status'), value: <span className={clsx('capitalize', statusConfig[selectedLog.status]?.text)}>{getStatusLabel(selectedLog.status)}</span> },
    { label: t('audit.detail.resourceType'), value: <span className="capitalize">{getResourceTypeLabel(selectedLog.resource_type)}</span> },
    { label: t('audit.detail.resourceId'), value: selectedLog.resource_id || '-', mono: true },
    { label: t('audit.detail.actor'), value: selectedLog.actor_name || '-' },
    { label: t('audit.detail.actorType'), value: <span className="capitalize">{selectedLog.actor_type || '-'}</span> },
    { label: t('audit.detail.ipAddress'), value: selectedLog.ip_address || '-', mono: true },
    { label: t('audit.detail.time'), value: formatDateTime(selectedLog.created_at, { withSeconds: true }) },
    { label: t('audit.detail.request'), value: `${selectedLog.request_method} ${selectedLog.request_path}`, mono: true, wide: true },
  ] : []

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('audit.list.title')}
        description={t('audit.list.subtitle')}
        actions={
          <>
            <IconButton
              variant="secondary"
              icon={RefreshCw}
              title={t('audit.list.refresh')}
              onClick={loadLogs}
              disabled={isLoading}
              className={clsx(isLoading && 'animate-spin')}
            />
            <div className="relative" ref={exportMenuRef}>
              <Button
                variant="secondary"
                icon={isExporting ? RefreshCw : Download}
                onClick={() => setShowExportMenu(!showExportMenu)}
                disabled={isExporting || isLoading}
                title={t('audit.list.exportTitle')}
                className={clsx(isExporting && '[&>svg]:animate-spin')}
              >
                {t('audit.list.export')}
                <ChevronDown className="h-3.5 w-3.5 text-subtle-foreground" aria-hidden="true" />
              </Button>
              {showExportMenu && (
                <div className="absolute right-0 z-50 mt-1 w-56 overflow-hidden rounded-md border border-border bg-popover py-1 shadow-overlay">
                  <button
                    type="button"
                    onClick={() => handleExport(100)}
                    className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm text-foreground transition-colors duration-200 hover:bg-muted"
                  >
                    <span>{t('audit.list.exportLatest100')}</span>
                    <span className="text-xs text-muted-foreground">{t('audit.list.exportLatest100Note')}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExport(10000)}
                    className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm text-foreground transition-colors duration-200 hover:bg-muted"
                  >
                    <span>{t('audit.list.exportAll')}</span>
                    <span className="text-xs text-muted-foreground">{t('audit.list.exportAllNote')}</span>
                  </button>
                </div>
              )}
            </div>
            <Button
              variant={showFilters || hasActiveFilters ? 'primary' : 'secondary'}
              icon={Filter}
              onClick={() => setShowFilters(!showFilters)}
            >
              {t('audit.list.filtersButton')}
              {hasActiveFilters && (
                <span className="inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded bg-white/20 px-1 text-xs tabular-nums">
                  {Object.values(filters).filter(Boolean).length}
                </span>
              )}
            </Button>
          </>
        }
      />

      {/* Filters panel */}
      {showFilters && (
        <Card padding="sm">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <Field label={t('audit.filters.action')}>
              <Select
                size="sm"
                value={filters.action}
                onChange={(e) => { setFilters(f => ({ ...f, action: e.target.value })); setPage(1) }}
              >
                <option value="">{t('audit.filters.allActions')}</option>
                {ACTION_KEYS.map((value) => (
                  <option key={value} value={value}>{getActionLabel(value)}</option>
                ))}
              </Select>
            </Field>
            <Field label={t('audit.filters.resourceType')}>
              <Select
                size="sm"
                value={filters.resourceType}
                onChange={(e) => { setFilters(f => ({ ...f, resourceType: e.target.value })); setPage(1) }}
              >
                <option value="">{t('audit.filters.allTypes')}</option>
                <option value="token">{t('audit.resourceType.token')}</option>
                <option value="oauth_client">{t('audit.resourceType.oauth_client')}</option>
                <option value="service">{t('audit.resourceType.service')}</option>
                <option value="admin">{t('audit.resourceType.admin')}</option>
                <option value="system">{t('audit.resourceType.system')}</option>
              </Select>
            </Field>
            <Field label={t('audit.filters.status')}>
              <Select
                size="sm"
                value={filters.status}
                onChange={(e) => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1) }}
              >
                <option value="">{t('audit.filters.allStatuses')}</option>
                <option value="success">{t('audit.status.success')}</option>
                <option value="failure">{t('audit.status.failure')}</option>
                <option value="error">{t('audit.status.error')}</option>
              </Select>
            </Field>
            <Field label={t('audit.filters.actor')}>
              <Input
                size="sm"
                type="text"
                value={filters.actorName}
                onChange={(e) => { setFilters(f => ({ ...f, actorName: e.target.value })); setPage(1) }}
                placeholder={t('audit.filters.actorPlaceholder')}
              />
            </Field>
          </div>
          {hasActiveFilters && (
            <div className="mt-3 flex justify-end">
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                {t('audit.filters.clearAll')}
              </Button>
            </div>
          )}
        </Card>
      )}

      {/* Error message */}
      {error && <Alert tone="danger">{error}</Alert>}

      {/* Logs table */}
      {isLoading ? (
        <LoadingBlock />
      ) : logs.length === 0 ? (
        <Card padding="none">
          <EmptyState
            icon={FileText}
            title={t('audit.list.empty')}
            description={hasActiveFilters ? t('audit.list.emptyAdjust') : t('audit.list.emptyHint')}
          />
        </Card>
      ) : (
        <Table className="min-w-[900px]">
          <THead>
            <TR hover={false} group={false}>
              <TH>{t('audit.list.columnTime')}</TH>
              <TH>{t('audit.list.columnAction')}</TH>
              <TH>{t('audit.list.columnResource')}</TH>
              <TH>{t('audit.list.columnActor')}</TH>
              <TH>{t('audit.list.columnStatus')}</TH>
              <TH>{t('audit.list.columnIP')}</TH>
            </TR>
          </THead>
          <TBody>
            {logs.map((log) => {
              const ResourceIcon = resourceTypeIcons[log.resource_type] || FileText
              const statusCfg = statusConfig[log.status] || statusConfig.error

              return (
                <TR
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className="cursor-pointer"
                >
                  <TD className="whitespace-nowrap font-mono text-xs tabular-nums" muted>
                    {formatDateTime(log.created_at, { withSeconds: true })}
                  </TD>
                  <TD focal className="whitespace-nowrap">
                    {getActionLabel(log.action)}
                  </TD>
                  <TD muted className="whitespace-nowrap">
                    <span className="inline-flex items-center gap-2 align-middle">
                      <ResourceIcon className="h-4 w-4 shrink-0 text-subtle-foreground" aria-hidden="true" />
                      <span className="capitalize">{getResourceTypeLabel(log.resource_type)}</span>
                    </span>
                  </TD>
                  <TD className="max-w-[16rem]">
                    <span className="block truncate" title={log.actor_name || ''}>{log.actor_name || '-'}</span>
                  </TD>
                  <TD className="whitespace-nowrap">
                    <StatusPill tone={statusCfg.tone} className="capitalize">
                      {getStatusLabel(log.status)}
                    </StatusPill>
                  </TD>
                  <TD mono muted className="whitespace-nowrap">
                    {log.ip_address || '-'}
                  </TD>
                </TR>
              )
            })}
          </TBody>
        </Table>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground tabular-nums">
            {t('audit.list.pageSummary', {
              from: ((page - 1) * pageSize) + 1,
              to: Math.min(page * pageSize, totalCount),
              total: totalCount,
            })}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              icon={ChevronLeft}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              aria-label={t('common.pagination.previous')}
            />
            <span className="px-1 text-xs text-muted-foreground tabular-nums">
              {t('audit.list.pageOf', { page, total: totalPages })}
            </span>
            <Button
              variant="secondary"
              size="sm"
              icon={ChevronRight}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              aria-label={t('common.pagination.next')}
            />
          </div>
        </div>
      )}

      {/* Log detail modal */}
      {selectedLog && (
        <Dialog open onClose={() => setSelectedLog(null)} size="2xl" title={t('audit.detail.title')}>
          <DialogBody className="space-y-5">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4">
              {detailItems.map(({ label, value, mono, wide }) => (
                <div key={label} className={clsx('min-w-0', wide && 'col-span-2')}>
                  <dt><SectionLabel>{label}</SectionLabel></dt>
                  <dd className={clsx('mt-1 break-all text-sm text-foreground', mono && 'font-mono text-xs')}>{value}</dd>
                </div>
              ))}
              {selectedLog.error_message && (
                <div className="col-span-2">
                  <dt><SectionLabel>{t('audit.detail.error')}</SectionLabel></dt>
                  <dd className="mt-1"><Alert tone="danger">{selectedLog.error_message}</Alert></dd>
                </div>
              )}
              {selectedLog.details && (
                <div className="col-span-2">
                  <dt><SectionLabel className="mb-1">{t('audit.detail.details')}</SectionLabel></dt>
                  <dd><CodeBlock value={selectedLog.details} language="json" /></dd>
                </div>
              )}
              <div className="col-span-2">
                <dt><SectionLabel>{t('audit.detail.userAgent')}</SectionLabel></dt>
                <dd className="mt-1 break-all text-xs text-muted-foreground">{selectedLog.user_agent || '-'}</dd>
              </div>
            </dl>
          </DialogBody>
        </Dialog>
      )}
    </div>
  )
}
