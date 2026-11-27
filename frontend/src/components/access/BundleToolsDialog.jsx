import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check } from 'lucide-react'
import { accessApi } from '../../services/api'
import { bundleChanges, toolScopeNames } from '../../utils/access'
import { Dialog, DialogBody, DialogFooter, Button, Badge, Checkbox, SectionLabel, Alert } from '../ui'

/**
 * Assign tools to a bundle (scope) from the bundle's side (#37). `servers` = [{ serviceId, name, access }]: one entry
 * on a server's Access tab, every server that may grant the scope on the Bundles page. Saving sends one
 * PUT .../tools/{id}/scopes per tool whose membership changed; the tool keeps its other bundles.
 */
export default function BundleToolsDialog({ scope, servers, onClose, onSaved }) {
  const { t } = useTranslation()
  const initial = useMemo(() => {
    const ids = new Set()
    for (const s of servers) for (const tool of s.access.tools) if (toolScopeNames(tool).includes(scope.name)) ids.add(tool.id)
    return ids
  }, [servers, scope.name])
  const [selected, setSelected] = useState(initial)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const toggle = (id) => setSelected((prev) => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })

  const plan = servers.map((s) => ({ ...s, changes: bundleChanges(s.access, scope.name, [...selected]) }))
  const changeCount = plan.reduce((n, s) => n + s.changes.length, 0)

  const save = async () => {
    setSaving(true)
    setError('')
    const failed = []
    for (const s of plan) {
      for (const c of s.changes) {
        try {
          await accessApi.setToolScopes(s.serviceId, c.toolId, c.body)
        } catch (err) {
          failed.push(`${s.name} · ${c.tool}: ${err.message}`)
        }
      }
    }
    setSaving(false)
    await onSaved?.()
    if (failed.length) setError(failed.join('\n'))
    else onClose()
  }

  return (
    <Dialog
      onClose={onClose}
      size="lg"
      title={t('access.bundleTools.title', { name: scope.title || scope.name })}
      description={t('access.bundleTools.subtitle', { scope: scope.name })}
    >
      <DialogBody className="space-y-5">
        {error && <Alert tone="danger"><span className="whitespace-pre-line">{error}</span></Alert>}
        {servers.length === 0 && <p className="text-sm text-muted-foreground">{t('access.bundleTools.noServers')}</p>}
        {servers.map((s) => {
          const tools = s.access.tools.filter((tl) => !tl.removed)
          return (
            <section key={s.serviceId} className="space-y-2">
              {servers.length > 1 || s.showName ? <SectionLabel>{s.name}</SectionLabel> : null}
              {tools.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t('access.bundleTools.noTools')}</p>
              ) : (
                <div className="divide-y divide-border rounded-md border border-border">
                  {tools.map((tool) => {
                    const others = toolScopeNames(tool).filter((n) => n !== scope.name)
                    return (
                      <label key={tool.id} className="flex cursor-pointer items-start gap-3 px-3 py-2.5 transition-colors duration-200 hover:bg-muted/60">
                        <Checkbox className="mt-0.5" checked={selected.has(tool.id)} onChange={() => toggle(tool.id)} data-testid={`bundle-tool-${tool.name}`} />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-1.5">
                            <span className="break-all font-mono text-xs font-medium text-foreground">{tool.name}</span>
                            {tool.state !== 'approved' && <Badge tone={tool.state === 'pending' ? 'warning' : 'danger'}>{t(`services.toolPin.state.${tool.state}`)}</Badge>}
                          </span>
                          {others.length > 0 && (
                            <span className="mt-0.5 block break-words text-[11px] text-muted-foreground">
                              {t('access.bundleTools.alsoIn', { list: others.join(', ') })}
                            </span>
                          )}
                        </span>
                      </label>
                    )
                  })}
                </div>
              )}
            </section>
          )
        })}
      </DialogBody>
      <DialogFooter between>
        <span className="text-xs text-muted-foreground">{t('access.bundleTools.changes', { count: changeCount })}</span>
        <span className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
          <Button variant="primary" size="sm" icon={Check} loading={saving} disabled={changeCount === 0} onClick={save}>{t('common.save')}</Button>
        </span>
      </DialogFooter>
    </Dialog>
  )
}
