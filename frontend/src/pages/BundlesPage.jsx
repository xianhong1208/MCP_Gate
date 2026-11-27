import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ListChecks, Package, Pencil, Plus, Trash2 } from 'lucide-react'
import { accessApi, oauthApi, servicesApi } from '../services/api'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import { allBundles } from '../utils/access'
import BundleToolsDialog from '../components/access/BundleToolsDialog'
import { BundleFormDialog, BundleName } from '../components/access/AccessDialogs'
import { PageHeader, Button, IconButton, Badge, Card, EmptyState, LoadingBlock, Alert } from '../components/ui'

/**
 * Bundles (#37): named sets of tools. A bundle is a scope; a token holding it may call the tools in it. Global
 * bundles can hold tools of every server that may grant them; a server's own bundle holds only its tools.
 */
export default function BundlesPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirmDelete } = useConfirm()
  const [data, setData] = useState(null)   // { services, accesses: {id: access}, globals }
  const [error, setError] = useState('')
  const [form, setForm] = useState(null)
  const [toolsFor, setToolsFor] = useState(null)

  const load = useCallback(async () => {
    const [s, g] = await Promise.all([servicesApi.getAll(), oauthApi.scopes.list()])
    const services = s.services || []
    const accesses = {}
    await Promise.all(services.map(async (svc) => {
      try { accesses[svc.id] = await accessApi.get(svc.id) } catch { /* a server that cannot be read is left out */ }
    }))
    setData({ services, accesses, globals: g.scopes || [] })
  }, [])
  useEffect(() => { load().catch((err) => setError(err.message)) }, [load])

  const { bundles, unused } = useMemo(() => (data ? allBundles(data) : { bundles: [], unused: [] }), [data])

  const submit = async (f) => {
    const fields = { description: f.description, isDefault: f.isDefault, title: f.title }
    const serviceId = form?.name ? form.service_id : f.serviceId
    if (serviceId) await oauthApi.serviceScopes.upsert(serviceId, f.name, fields)
    else await oauthApi.scopes.upsert(f.name, fields)
    toast.success(t('access.bundles.saved'))
    await load()
  }

  const remove = async (b) => {
    if (!(await confirmDelete(t('access.bundles.deleteTarget', { name: b.name, count: b.toolCount })))) return
    try {
      if (b.service_id) await oauthApi.serviceScopes.delete(b.service_id, b.name)
      else await oauthApi.scopes.delete(b.name)
      toast.success(t('access.bundles.deleted'))
      await load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  const serverEntries = (b) => b.servers.map((s) => ({ serviceId: s.id, name: s.name, access: data.accesses[s.id], showName: !b.service_id }))

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('bundles.title')}
        description={t('bundles.subtitle')}
        actions={<Button variant="primary" icon={Plus} onClick={() => setForm({})} disabled={!data} data-testid="add-bundle">{t('access.bundles.add')}</Button>}
      />
      {error && <Alert tone="danger">{error}</Alert>}
      {!data ? (
        !error && <LoadingBlock className="min-h-[200px]" />
      ) : bundles.length === 0 ? (
        <Card><EmptyState icon={Package} title={t('access.bundles.empty')} description={t('bundles.emptyHint')} /></Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {bundles.map((b) => (
            <Card key={`${b.service_id || 'global'}:${b.name}`} className="flex min-w-0 flex-col" data-testid={`bundle-${b.name}`}>
              <div className="flex items-start gap-2">
                <div className="min-w-0 flex-1">
                  <BundleName scope={b} className="block text-sm" />
                  <div className="mt-1 flex flex-wrap items-center gap-1">
                    <Badge tone={b.service_id ? 'accent' : 'neutral'}>{b.service_id ? t('bundles.onlyOn', { name: b.servers[0]?.name || '?' }) : t('access.source.global')}</Badge>
                    {b.is_default && <Badge tone="success">{t('clients.scopes.default')}</Badge>}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-0.5">
                  <IconButton icon={ListChecks} title={t('access.bundles.editTools')} onClick={() => setToolsFor(b)} disabled={b.servers.length === 0} data-testid={`bundle-tools-${b.name}`} />
                  <IconButton icon={Pencil} title={t('common.edit')} onClick={() => setForm(b)} />
                  <IconButton variant="destructive" icon={Trash2} title={t('common.delete')} onClick={() => remove(b)} />
                </div>
              </div>
              {b.description && <p className="mt-2 text-xs text-muted-foreground">{b.description}</p>}
              <div className="mt-3 flex-1 space-y-2 border-t border-border pt-3">
                {b.toolCount === 0 ? (
                  <p className="text-xs text-muted-foreground">{b.servers.length ? t('bundles.noTools') : t('bundles.noServers')}</p>
                ) : b.servers.filter((s) => s.tools.length).map((s) => (
                  <div key={s.id} className="min-w-0">
                    <Link to={`/services/${encodeURIComponent(s.id)}?tab=access`} className="text-xs font-medium text-link transition-colors duration-200 hover:text-link-hover">{s.name}</Link>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {s.tools.map((n) => <Badge key={n} tone="neutral" mono>{n}</Badge>)}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>
      )}
      {data && unused.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {t('bundles.otherScopes', { count: unused.length, list: unused.join(', ') })}
        </p>
      )}
      {form && (
        <BundleFormDialog bundle={form.name ? form : null} servers={data?.services || []} onClose={() => setForm(null)} onSubmit={submit} />
      )}
      {toolsFor && (
        <BundleToolsDialog scope={toolsFor} servers={serverEntries(toolsFor)} onClose={() => setToolsFor(null)} onSaved={load} />
      )}
    </div>
  )
}
