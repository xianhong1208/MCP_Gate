import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Server, Plus, Trash2, Key, RefreshCw, Check, Download,
  Radio, Search, Activity, Wrench, Copy, Edit3, Lock,
} from 'lucide-react'
import { servicesApi, discoveryApi, oauthApi } from '../services/api'
import { exportServicesToCSV } from '../utils/export'
import { formatMs } from '../utils/format'
import { copyToClipboard } from '../utils/clipboard'
import useVisiblePolling from '../hooks/usePolling'
import LastChecked from '../components/LastChecked'
import ServiceFormModal from '../components/ServiceFormModal'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import HealthIndicator from '../components/HealthIndicator'
import clsx from 'clsx'
import {
  PageHeader, Button, IconButton, Badge, StatusPill, Card, EmptyState, Alert, LoadingBlock,
  Table, THead, TBody, TR, TH, TD, RowActions, Checkbox,
  Dialog, DialogBody, DialogFooter, Field, Input, Radio as RadioInput, CheckRow,
} from '../components/ui'

// Tools modal (for services protected by MCP Center the backend self-signs a token to fetch tools; no token to pick)
function ToolsModal({ service, onClose }) {
  const { t } = useTranslation()
  const [tools, setTools] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [refreshError, setRefreshError] = useState('')
  const toast = useToast()

  useEffect(() => {
    let cancelled = false
    setIsLoading(true)
    setError('')
    servicesApi.getTools(service.id)
      .then((result) => { if (!cancelled) setTools(result.tools || []) })
      .catch((err) => { if (!cancelled) setError(err.message || t('services.tools.loadFailed')) })
      .finally(() => { if (!cancelled) setIsLoading(false) })
    return () => { cancelled = true }
  }, [service.id, t])

  const handleRefresh = async () => {
    setIsRefreshing(true)
    setRefreshError('')
    try {
      const result = await servicesApi.refreshTools(service.id)
      setTools(result.tools || [])
      toast.success(t('services.tools.refreshSuccess', { n: result.tools_count }))
    } catch (err) {
      setRefreshError(err.message || t('services.tools.refreshFailed'))
    } finally {
      setIsRefreshing(false)
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="2xl"
      title={t('services.tools.title', { name: service.name })}
      description={service.mcp_url ? <span className="font-mono">{service.mcp_url}</span> : t('services.tools.noConnection')}
    >
      <DialogBody className="space-y-4">
        {refreshError && <Alert tone="danger">{refreshError}</Alert>}

        {isLoading ? (
          <LoadingBlock />
        ) : error ? (
          <Alert tone="danger">{error}</Alert>
        ) : tools.length === 0 ? (
          <EmptyState
            compact
            icon={Wrench}
            title={t('services.common.noTools')}
            description={service.host && service.port ? t('services.common.refreshHint') : undefined}
          />
        ) : (
          <div className="divide-y divide-border rounded-md border border-border">
            {tools.map((tool) => (
              <div key={tool.id || tool.name} className="px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <h4 className="font-mono text-xs font-medium text-foreground">{tool.name}</h4>
                    {tool.description && <p className="mt-1 text-sm text-muted-foreground">{tool.description}</p>}
                  </div>
                  {tool.input_schema && (
                    <IconButton
                      icon={Copy}
                      size="sm"
                      onClick={() => {
                        copyToClipboard(JSON.stringify(tool.input_schema, null, 2))
                        toast.success(t('services.common.schemaCopied'))
                      }}
                      title={t('services.common.copyInputSchema')}
                    />
                  )}
                </div>
                {tool.input_schema && (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">{t('services.common.inputSchema')}</summary>
                    <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-muted/50 p-3 font-mono text-xs text-foreground">
                      {JSON.stringify(tool.input_schema, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </DialogBody>

      <DialogFooter between>
        <span className="text-xs text-muted-foreground tabular-nums">{t('services.common.toolsCount', { n: tools.length, count: tools.length })}</span>
        <div className="flex items-center gap-2">
          {service.host && service.port && (
            <Button variant="secondary" icon={RefreshCw} onClick={handleRefresh} loading={isRefreshing}>
              {t('services.tools.refreshFromServer')}
            </Button>
          )}
          <Button variant="primary" onClick={onClose}>{t('services.common.close')}</Button>
        </div>
      </DialogFooter>
    </Dialog>
  )
}

// Scan services modal
function ScanModal({ onClose, onScanComplete }) {
  const { t } = useTranslation()
  const [formData, setFormData] = useState({
    hosts: 'localhost',
    portMode: 'individual',
    ports: '3000,8000,8080',
    portRangeStart: 3000,
    portRangeEnd: 3500,
    autoRegister: true,
  })
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [error, setError] = useState('')

  const handleScan = async (e) => {
    e.preventDefault()
    setError('')
    setIsScanning(true)
    setScanResult(null)
    try {
      const hosts = formData.hosts.split(',').map((h) => h.trim()).filter(Boolean)
      const scanParams = { hosts, autoRegister: formData.autoRegister }
      if (formData.portMode === 'individual') {
        scanParams.ports = formData.ports.split(',').map((p) => parseInt(p.trim(), 10)).filter((p) => !isNaN(p))
      } else {
        scanParams.ports = []
        scanParams.portRangeStart = formData.portRangeStart
        scanParams.portRangeEnd = formData.portRangeEnd
      }
      const result = await discoveryApi.scan(scanParams)
      setScanResult(result)
      if (result.registered_count > 0) onScanComplete()
    } catch (err) {
      setError(err.message || t('services.scan.scanFailed'))
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <Dialog open onClose={onClose} size="lg" title={t('services.scan.title')}>
      {!scanResult ? (
        <form onSubmit={handleScan} className="flex min-h-0 flex-1 flex-col">
          <DialogBody className="space-y-5">
            {error && <Alert tone="danger">{error}</Alert>}

            <Field label={t('services.scan.hostsLabel')}>
              <Input type="text" value={formData.hosts} onChange={(e) => setFormData({ ...formData, hosts: e.target.value })} placeholder={t('services.scan.hostsPlaceholder')} />
            </Field>

            <Field
              label={t('services.scan.portModeLabel')}
              help={formData.portMode === 'individual' ? t('services.scan.individualHint') : t('services.scan.rangeHint')}
            >
              <div className="mb-3 flex gap-5">
                {['individual', 'range'].map((mode) => (
                  <label key={mode} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
                    <RadioInput name="portMode" value={mode} checked={formData.portMode === mode}
                      onChange={(e) => setFormData({ ...formData, portMode: e.target.value })} />
                    {mode === 'individual' ? t('services.scan.individualPorts') : t('services.scan.portRange')}
                  </label>
                ))}
              </div>
              {formData.portMode === 'individual' ? (
                <Input type="text" value={formData.ports} onChange={(e) => setFormData({ ...formData, ports: e.target.value })} placeholder={t('services.scan.individualPortsPlaceholder')} mono />
              ) : (
                <div className="flex items-center gap-3">
                  <Input type="number" value={formData.portRangeStart} onChange={(e) => setFormData({ ...formData, portRangeStart: parseInt(e.target.value, 10) || 0 })} className="w-28" placeholder={t('services.scan.rangeStart')} min="1" max="65535" />
                  <span className="text-sm text-muted-foreground">{t('services.scan.rangeTo')}</span>
                  <Input type="number" value={formData.portRangeEnd} onChange={(e) => setFormData({ ...formData, portRangeEnd: parseInt(e.target.value, 10) || 0 })} className="w-28" placeholder={t('services.scan.rangeEnd')} min="1" max="65535" />
                  <span className="text-xs text-muted-foreground tabular-nums">{t('services.scan.portsRangeCount', { n: Math.max(0, formData.portRangeEnd - formData.portRangeStart + 1) })}</span>
                </div>
              )}
            </Field>

            <CheckRow
              checked={formData.autoRegister}
              onChange={(e) => setFormData({ ...formData, autoRegister: e.target.checked })}
              label={t('services.scan.autoRegister')}
            />
          </DialogBody>

          <DialogFooter>
            <Button type="button" variant="secondary" onClick={onClose}>{t('services.common.cancel')}</Button>
            <Button type="submit" variant="primary" icon={Search} loading={isScanning}>
              {isScanning ? t('services.common.scanning') : t('services.scan.startScan')}
            </Button>
          </DialogFooter>
        </form>
      ) : (
        <>
          <DialogBody className="space-y-4">
            <Alert tone="success">
              {t('services.scan.foundServices', { count: scanResult.discovered.length })}
              {scanResult.registered_count > 0 && t('services.scan.registeredServices', { count: scanResult.registered_count })}
            </Alert>

            {scanResult.discovered.some((s) => s.server_name === '(requires auth)') && (
              <Alert tone="warning" title={t('services.scan.authRequiredTitle')}>
                {t('services.scan.authRequiredHint')}
              </Alert>
            )}

            {scanResult.discovered.length > 0 && (
              <div className="divide-y divide-border rounded-md border border-border">
                {scanResult.discovered.map((svc, i) => {
                  const requiresAuth = svc.server_name === '(requires auth)'
                  return (
                    <div key={i} className="flex items-center justify-between gap-4 px-4 py-3">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs text-foreground">{svc.protocol}://{svc.host}:{svc.port}{svc.mcp_path}</p>
                        {requiresAuth ? (
                          <p className="mt-0.5 text-xs text-warning">{t('services.scan.requiresAuthLabel')}</p>
                        ) : svc.requires_auth && svc.server_name ? (
                          <p className="mt-0.5 text-xs text-muted-foreground">
                            {svc.server_name}{svc.server_version ? ` v${svc.server_version}` : ''} · {t('services.scan.protectedLabel')}
                          </p>
                        ) : svc.server_name && (
                          <p className="mt-0.5 text-xs text-muted-foreground">{svc.server_name} {svc.server_version && `v${svc.server_version}`}</p>
                        )}
                      </div>
                      <div className="flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
                        {svc.tools_count > 0 && (
                          <span className="inline-flex items-center gap-1"><Wrench className="h-3 w-3" />{t('services.scan.toolsCount', { n: svc.tools_count })}</span>
                        )}
                        {svc.registered ? (
                          <Badge tone="success"><Check className="h-3 w-3" />{t('services.scan.registered')}</Badge>
                        ) : svc.service_name ? (
                          <Badge tone="neutral">{t('services.scan.alreadyExists')}</Badge>
                        ) : null}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="primary" onClick={onClose}>{t('services.common.close')}</Button>
          </DialogFooter>
        </>
      )}
    </Dialog>
  )
}

export default function ServicesPage() {
  const { t } = useTranslation()
  const { confirmDelete, confirmBatchDelete } = useConfirm()
  const toast = useToast()
  const [services, setServices] = useState([])
  const [scopes, setScopes] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showScanModal, setShowScanModal] = useState(false)
  const [editingService, setEditingService] = useState(null)
  const [viewingToolsService, setViewingToolsService] = useState(null)
  const [selectedServices, setSelectedServices] = useState(new Set())
  const [isBatchDeleting, setIsBatchDeleting] = useState(false)
  const [checkingHealth, setCheckingHealth] = useState(new Set())
  const [checkingAll, setCheckingAll] = useState(false)

  const toggleServiceSelection = (serviceId) => {
    setSelectedServices((prev) => {
      const next = new Set(prev)
      if (next.has(serviceId)) next.delete(serviceId)
      else next.add(serviceId)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedServices.size === services.length) setSelectedServices(new Set())
    else setSelectedServices(new Set(services.map((s) => s.id)))
  }

  const loadData = useCallback(async ({ silent = false } = {}) => {
    if (!silent) {
      setIsLoading(true)
      setError(null)
    }
    try {
      const res = await servicesApi.getAll()
      setServices(res.services || [])
    } catch (err) {
      setError(err.message || t('services.list.loadFailed'))
    } finally {
      if (!silent) setIsLoading(false)
    }
  }, [t])

  useEffect(() => { loadData() }, [loadData])
  useEffect(() => {
    oauthApi.scopes.list().then((r) => setScopes(r.scopes || [])).catch(() => {})
  }, [])

  // Health is updated by the scheduler in the background; silently refresh every 20s while the tab is visible
  useVisiblePolling(() => loadData({ silent: true }), 20000)

  const handleBatchDelete = async () => {
    if (selectedServices.size === 0) return
    const confirmed = await confirmBatchDelete(selectedServices.size, t('services.common.serviceLabel'))
    if (!confirmed) return
    setIsBatchDeleting(true)
    try {
      await Promise.all([...selectedServices].map((id) => servicesApi.delete(id)))
      toast.success(t('services.list.batchDeleteSuccess', { n: selectedServices.size }))
      setSelectedServices(new Set())
      await loadData()
    } catch (err) {
      toast.error(err.message || t('services.list.batchDeleteFailed'))
    } finally {
      setIsBatchDeleting(false)
    }
  }

  const handleCheckAllHealth = async () => {
    setCheckingAll(true)
    try {
      const r = await servicesApi.checkAllHealth()
      toast.success(t('services.list.checkAllDone', {
        checked: r.checked ?? 0, online: r.online ?? 0, offline: (r.offline ?? 0) + (r.error ?? 0),
      }))
      await loadData({ silent: true })
    } catch (err) {
      toast.error(err.message || t('services.list.checkAllFailed'))
    } finally {
      setCheckingAll(false)
    }
  }

  const handleCreate = async (fields) => {
    await servicesApi.create(fields)
    await loadData()
    toast.success(t('services.list.createSuccess', { name: fields.name }))
  }

  const handleUpdate = async (serviceId, fields) => {
    const service = services.find((s) => s.id === serviceId)
    await servicesApi.update(serviceId, fields)
    await loadData()
    toast.success(t('services.list.updateSuccess', { name: service?.name || serviceId }))
  }

  const handleDelete = async (serviceId, serviceName) => {
    const confirmed = await confirmDelete(t('services.common.serviceWithName', { name: serviceName }))
    if (!confirmed) return
    try {
      await servicesApi.delete(serviceId)
      await loadData()
      toast.success(t('services.list.deleteSuccess', { name: serviceName }))
    } catch (err) {
      toast.error(err.message || t('services.list.deleteFailed'))
    }
  }

  const handleCheckHealth = async (serviceId, serviceName) => {
    setCheckingHealth((prev) => new Set(prev).add(serviceId))
    try {
      const result = await servicesApi.checkHealth(serviceId)
      toast.success(t('services.common.healthCheckResult', { name: serviceName, status: result.status }))
      await loadData({ silent: true })
    } catch (err) {
      toast.error(t('services.common.healthCheckFailed', { message: err.message }))
    } finally {
      setCheckingHealth((prev) => {
        const next = new Set(prev)
        next.delete(serviceId)
        return next
      })
    }
  }

  const allSelected = services.length > 0 && selectedServices.size === services.length
  const someSelected = selectedServices.size > 0 && !allSelected

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('services.list.title')}
        description={t('services.list.subtitle')}
        actions={
          <>
            <IconButton
              variant="secondary"
              icon={RefreshCw}
              title={t('services.list.refresh')}
              onClick={() => loadData()}
              disabled={isLoading}
              className={clsx(isLoading && 'animate-spin')}
            />
            {services.length > 0 && (
              <IconButton variant="secondary" icon={Download} title={t('services.list.exportTitle')} onClick={() => exportServicesToCSV(services)} />
            )}
            <Button variant="secondary" icon={Activity} onClick={handleCheckAllHealth} disabled={isLoading} loading={checkingAll} title={t('services.list.checkAllTitle')}>
              {checkingAll ? t('services.list.checkingAll') : t('services.list.checkAll')}
            </Button>
            <Button variant="secondary" icon={Radio} onClick={() => setShowScanModal(true)}>
              {t('services.list.scan')}
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setShowCreateModal(true)}>
              {t('services.list.registerService')}
            </Button>
          </>
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}

      {selectedServices.size > 0 && (
        <div className="flex h-12 items-center justify-between rounded-lg border border-border bg-card px-4">
          <div className="flex items-center gap-3 text-sm">
            <span className="font-medium text-foreground tabular-nums">{t('services.list.selectedCount', { n: selectedServices.size })}</span>
            <button type="button" onClick={() => setSelectedServices(new Set())} className="text-muted-foreground transition-colors duration-200 hover:text-foreground">
              {t('services.list.clearSelection')}
            </button>
          </div>
          <Button variant="destructive" size="sm" icon={Trash2} onClick={handleBatchDelete} loading={isBatchDeleting}>
            {t('services.list.deleteSelected')}
          </Button>
        </div>
      )}

      {isLoading ? (
        <LoadingBlock />
      ) : error ? null : services.length === 0 ? (
        <Card padding="none">
          <EmptyState
            icon={Server}
            title={t('services.list.emptyTitle')}
            description={t('services.list.emptyHint')}
            action={
              <>
                <Button variant="secondary" icon={Radio} onClick={() => setShowScanModal(true)}>{t('services.list.scanNetwork')}</Button>
                <Button variant="soft" icon={Plus} onClick={() => setShowCreateModal(true)}>{t('services.list.registerService')}</Button>
              </>
            }
          />
        </Card>
      ) : (
        <Table>
          <THead>
            <TR hover={false} group={false}>
              <TH className="w-10 pr-0">
                <Checkbox
                  checked={allSelected}
                  ref={(el) => { if (el) el.indeterminate = someSelected }}
                  onChange={toggleSelectAll}
                  aria-label={allSelected ? t('services.list.deselectAll') : t('services.list.selectAll')}
                />
              </TH>
              <TH>{t('services.list.colName')}</TH>
              <TH>{t('services.list.colStatus')}</TH>
              <TH>{t('services.list.colAudience')}</TH>
              <TH align="right">{t('services.list.colTools')}</TH>
              <TH align="right" className="w-56" />
            </TR>
          </THead>
          <TBody>
            {services.map((service) => {
              const isSelected = selectedServices.has(service.id)
              const isCheckingHealth = checkingHealth.has(service.id)
              const health = service.health
              return (
                <TR key={service.id} selected={isSelected}>
                  <TD className="pr-0">
                    <Checkbox checked={isSelected} onChange={() => toggleServiceSelection(service.id)} aria-label={service.name} />
                  </TD>
                  <TD className="max-w-xs">
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/services/${encodeURIComponent(service.id)}`}
                        className="truncate font-medium text-foreground transition-colors duration-200 hover:text-link"
                        title={service.name}
                      >
                        {service.name}
                      </Link>
                      {service.source === 'auto_discovered' && <Badge tone="warning">{t('services.list.autoTag')}</Badge>}
                      {service.source === 'managed' && <Badge tone="accent">{t('services.list.managedTag')}</Badge>}
                      {service.requires_auth ? (
                        <Badge tone="neutral" title={t('services.list.oauthBadge')}><Key className="h-3 w-3" />{t('services.list.oauthBadge')}</Badge>
                      ) : (
                        <Badge tone="neutral">{t('services.list.noAuthBadge')}</Badge>
                      )}
                      {service.has_static_token && (
                        <Badge tone="neutral" title={t('services.list.staticTokenTitle')}><Lock className="h-3 w-3" /></Badge>
                      )}
                    </div>
                    <div className="mt-0.5 truncate text-xs text-muted-foreground" title={service.mcp_url || service.description || ''}>
                      {service.mcp_url ? <span className="font-mono">{service.mcp_url}</span> : (service.description || t('services.common.noDescription'))}
                    </div>
                  </TD>
                  <TD>
                    <div className="flex flex-col gap-0.5">
                      <HealthIndicator status={health?.status} />
                      <span className="flex items-center gap-2 pl-3 text-xs text-subtle-foreground">
                        <LastChecked value={health?.last_checked} withIcon={false} className="text-subtle-foreground" />
                        {health?.response_time_ms != null && (
                          <span className="font-mono tabular-nums" title={t('services.list.responseTime')}>{formatMs(health.response_time_ms)}</span>
                        )}
                      </span>
                    </div>
                  </TD>
                  <TD className="max-w-[16rem]">
                    <div className="truncate font-mono text-xs text-muted-foreground" title={service.effective_audience || ''}>
                      {service.effective_audience || '—'}
                    </div>
                    {service.tags && service.tags.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {service.tags.map((tag) => <Badge key={tag} tone="neutral">{tag}</Badge>)}
                      </div>
                    )}
                  </TD>
                  <TD align="right" className="tabular-nums text-muted-foreground">
                    {service.tools_count ?? 0}
                  </TD>
                  <TD align="right">
                    <RowActions>
                      <IconButton icon={Wrench} title={t('services.list.viewTools')} onClick={() => setViewingToolsService(service)} />
                      <IconButton
                        icon={isCheckingHealth ? RefreshCw : Activity}
                        title={t('services.list.checkHealth')}
                        onClick={() => handleCheckHealth(service.id, service.name)}
                        disabled={isCheckingHealth || !service.host}
                        className={clsx(isCheckingHealth && 'animate-spin')}
                      />
                      <IconButton icon={Edit3} title={t('services.list.editService')} onClick={() => setEditingService(service)} />
                      <IconButton icon={Key} title={t('services.list.issueToken')} to={`/tokens/create?service_id=${encodeURIComponent(service.id)}`} />
                      <span className="mx-1 h-4 w-px bg-border" aria-hidden="true" />
                      <IconButton variant="destructive" icon={Trash2} title={t('services.list.deleteService')} onClick={() => handleDelete(service.id, service.name)} />
                    </RowActions>
                  </TD>
                </TR>
              )
            })}
          </TBody>
        </Table>
      )}

      {showCreateModal && (
        <ServiceFormModal mode="create" scopes={scopes} onClose={() => setShowCreateModal(false)} onSubmit={handleCreate} />
      )}
      {showScanModal && <ScanModal onClose={() => setShowScanModal(false)} onScanComplete={loadData} />}
      {editingService && (
        <ServiceFormModal
          mode="edit"
          service={editingService}
          scopes={scopes}
          onClose={() => setEditingService(null)}
          onSubmit={(fields) => handleUpdate(editingService.id, fields)}
        />
      )}
      {viewingToolsService && <ToolsModal service={viewingToolsService} onClose={() => setViewingToolsService(null)} />}
    </div>
  )
}
