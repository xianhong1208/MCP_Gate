import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Ban, ListChecks, Package, Pencil, Plus, ShieldCheck, Trash2, Wrench } from 'lucide-react'
import clsx from 'clsx'
import { accessApi, groupsApi, oauthApi, usersApi } from '../../services/api'
import { useConfirm } from '../../contexts/ConfirmContext'
import { useToast } from '../../contexts/ToastContext'
import { formatDateTime } from '../../utils/format'
import {
  ALL_TOOLS, bundlesFromAccess, enforcement, rulesForTool, subjectLabel, subjectOptions, toolScopeNames,
} from '../../utils/access'
import LastChecked from '../LastChecked'
import BundleToolsDialog from './BundleToolsDialog'
import { BundleFormDialog, BundleName, RuleDialog, ToolScopesDialog } from './AccessDialogs'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, IconButton, SegmentedControl } from '../ui'

const EFFECT_TONE = { deny: 'danger', only: 'info' }

/** Whether what is set on this tab reaches the server (#76's indicator, prominent at the top of the tab). */
function EnforcementBanner({ status }) {
  const { t } = useTranslation()
  const e = enforcement(status)
  if (!e) return null
  return (
    <Alert tone={e.tone} icon={e.key === 'enforced' ? ShieldCheck : undefined} title={t(`access.enforcement.${e.key}.title`)}>
      <span data-testid="access-enforcement" data-state={e.key}>
        {t(`access.enforcement.${e.key}.body`)}
        {status.last_poll && (e.key === 'enforced' || e.key === 'stale') && (
          <> {t('access.enforcement.lastPoll')} <LastChecked value={status.last_poll} withIcon={false} className="text-foreground" /></>
        )}
      </span>
    </Alert>
  )
}

/** A tool's bundles as chips; the one a step-up challenge names is marked. */
function ToolBundles({ tool, scopes }) {
  const { t } = useTranslation()
  const names = toolScopeNames(tool)
  if (names.length === 0) return <span className="text-xs text-subtle-foreground">{t('access.tools.noBundle')}</span>
  return (
    <span className="flex flex-wrap gap-1">
      {names.map((n) => {
        const s = scopes.find((x) => x.name === n)
        const isChallenge = tool.challenge === n
        return (
          <Badge key={n} tone={isChallenge ? 'accent' : 'neutral'} mono title={[s?.title, isChallenge ? t('access.tools.challengeHint') : null].filter(Boolean).join(' · ')}>
            {n}{isChallenge && <span aria-label={t('access.tools.challengeHint')}>↑</span>}
          </Badge>
        )
      })}
    </span>
  )
}

/**
 * A server's Access tab (#37): enforcement, the default for tools in no bundle, each tool's bundles, the bundles
 * available here, and the deny / "only" rules. `access` is GET /api/services/{id}/access; `onChanged` reloads it.
 */
export default function AccessPanel({ service, access, policyStatus, tokens, onChanged }) {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirm, confirmDelete } = useConfirm()
  const [settingUnscoped, setSettingUnscoped] = useState(false)
  const [editTool, setEditTool] = useState(null)
  const [editBundleTools, setEditBundleTools] = useState(null)
  const [bundleForm, setBundleForm] = useState(null)     // {} = new, scope = edit
  const [ruleDialog, setRuleDialog] = useState(null)     // {} = new, rule = edit
  const [lists, setLists] = useState({ clients: [], users: [], groups: [] })

  useEffect(() => {
    let cancelled = false
    Promise.all([
      oauthApi.clients.list('active').catch(() => ({ clients: [] })),
      usersApi.list().catch(() => ({ users: [] })),
      groupsApi.list().catch(() => ({ groups: [] })),
    ]).then(([c, u, g]) => {
      if (!cancelled) setLists({ clients: c.clients || [], users: u.users || [], groups: g.groups || [] })
    })
    return () => { cancelled = true }
  }, [])

  const subjects = useMemo(() => subjectOptions({ tokens, ...lists }), [tokens, lists])
  const bundles = useMemo(() => bundlesFromAccess(access), [access])
  const tools = access.tools.filter((tl) => !tl.removed)
  const activeRules = access.rules.filter((r) => !r.expired)

  const setUnscoped = async (value) => {
    if (value === access.unscoped_tools) return
    const unbundled = tools.filter((tl) => tl.state === 'approved' && toolScopeNames(tl).length === 0)
    if (value === 'require' && unbundled.length > 0) {
      const ok = await confirm({
        title: t('access.unscoped.confirmTitle', { count: unbundled.length }),
        message: t('access.unscoped.confirmMessage', { list: unbundled.map((tl) => tl.name).join(', ') }),
        confirmText: t('access.unscoped.confirmButton'),
        type: 'warning',
      })
      if (!ok) return
    }
    setSettingUnscoped(true)
    try {
      await accessApi.setUnscopedTools(service.id, value)
      toast.success(t('access.unscoped.saved'))
      await onChanged()
    } catch (err) {
      toast.error(err.message)
    } finally {
      setSettingUnscoped(false)
    }
  }

  const saveBundle = async (form) => {
    await oauthApi.serviceScopes.upsert(service.id, form.name, { description: form.description, isDefault: form.isDefault, title: form.title })
    toast.success(t('access.bundles.saved'))
    await onChanged()
  }

  const deleteBundle = async (scope) => {
    const ok = await confirmDelete(t('access.bundles.deleteTarget', { name: scope.name, count: scope.tools.length }))
    if (!ok) return
    try {
      await oauthApi.serviceScopes.delete(service.id, scope.name)
      toast.success(t('access.bundles.deleted'))
      await onChanged()
    } catch (err) {
      toast.error(err.message)
    }
  }

  const deleteRule = async (rule) => {
    const ok = await confirmDelete(t('access.rules.deleteTarget', { subject: subjectLabel(rule.subject) }))
    if (!ok) return
    try {
      await accessApi.deleteRule(service.id, rule.id)
      toast.success(t('access.rules.deleted'))
      await onChanged()
    } catch (err) {
      toast.error(err.message)
    }
  }

  const visibleBundles = bundles.filter((b) => b.tools.length > 0 || b.source === 'service')

  return (
    <div className="space-y-4" data-testid="access-panel">
      <EnforcementBanner status={policyStatus} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {/* Tools and their bundles */}
          <Card>
            <CardHeader
              title={t('access.tools.title')}
              description={t('access.tools.subtitle')}
            />
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 px-3 py-2.5">
              <div className="min-w-0">
                <p className="text-sm font-medium text-foreground">{t('access.unscoped.label')}</p>
                <p className="text-xs text-muted-foreground">{t(`access.unscoped.help.${access.unscoped_tools}`)}</p>
              </div>
              <span className={clsx(settingUnscoped && 'pointer-events-none opacity-60')} data-testid="unscoped-switch" data-value={access.unscoped_tools}>
                <SegmentedControl
                  size="sm"
                  value={access.unscoped_tools}
                  onChange={setUnscoped}
                  items={[{ key: 'allow', label: t('access.unscoped.allow') }, { key: 'require', label: t('access.unscoped.require') }]}
                />
              </span>
            </div>
            {tools.length === 0 ? (
              <EmptyState compact icon={Wrench} title={t('access.tools.empty')} description={t('services.common.refreshServerHint')} />
            ) : (
              <div className="divide-y divide-border">
                {tools.map((tool) => {
                  const rules = rulesForTool(activeRules, tool.name)
                  const hidden = access.unscoped_tools === 'require' && toolScopeNames(tool).length === 0
                  return (
                    <div key={tool.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5" data-testid={`access-tool-${tool.name}`}>
                      <div className="min-w-0 flex-1 basis-48">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="break-all font-mono text-xs font-medium text-foreground">{tool.name}</span>
                          {tool.state !== 'approved' && <Badge tone={tool.state === 'pending' ? 'warning' : 'danger'}>{t(`services.toolPin.state.${tool.state}`)}</Badge>}
                          {hidden && <Badge tone="warning" title={t('access.tools.hiddenHint')}>{t('access.tools.hidden')}</Badge>}
                          {rules.length > 0 && <Badge tone="neutral" title={rules.map((r) => `${t(`access.rules.effect.${r.effect}`)}: ${subjectLabel(r.subject)}`).join('\n')}>{t('access.tools.rules', { count: rules.length })}</Badge>}
                        </div>
                      </div>
                      <div className="flex min-w-0 items-center gap-2">
                        <ToolBundles tool={tool} scopes={access.scopes} />
                        <IconButton icon={Pencil} title={t('access.tools.edit')} onClick={() => setEditTool(tool)} data-testid={`edit-tool-${tool.name}`} />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </Card>

          {/* Rules */}
          <Card>
            <CardHeader
              title={t('access.rules.title')}
              description={t('access.rules.subtitle')}
              action={<Button variant="secondary" size="sm" icon={Plus} onClick={() => setRuleDialog({})} disabled={tools.length === 0} data-testid="add-rule">{t('access.rules.add')}</Button>}
            />
            {access.rules.length === 0 ? (
              <EmptyState compact icon={Ban} title={t('access.rules.empty')} description={t('access.rules.emptyHint')} />
            ) : (
              <div className="divide-y divide-border">
                {access.rules.map((rule) => (
                  <div key={rule.id} className={clsx('group flex items-start gap-3 py-3', rule.expired && 'opacity-60')} data-testid="access-rule">
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge tone={EFFECT_TONE[rule.effect] || 'neutral'}>{t(`access.rules.effect.${rule.effect}`)}</Badge>
                        <Badge tone="neutral">{t(`access.subject.${rule.subject.kind}`)}</Badge>
                        <span className="min-w-0 break-all text-sm font-medium text-foreground" title={rule.subject.id}>{subjectLabel(rule.subject)}</span>
                        {rule.expired && <Badge tone="warning">{t('access.rules.expired')}</Badge>}
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {rule.tools.includes(ALL_TOOLS)
                          ? <Badge tone="danger">{t('access.rules.allTools')}</Badge>
                          : rule.tools.map((n) => <Badge key={n} tone="neutral" mono>{n}</Badge>)}
                      </div>
                      {(rule.note || rule.expires_at) && (
                        <p className="text-xs text-muted-foreground">
                          {rule.note}
                          {rule.note && rule.expires_at && ' · '}
                          {rule.expires_at && t(rule.expired ? 'access.rules.expiredAt' : 'access.rules.expiresAt', { when: formatDateTime(rule.expires_at) })}
                        </p>
                      )}
                    </div>
                    <div className="flex shrink-0 items-center gap-0.5">
                      <IconButton icon={Pencil} title={t('common.edit')} onClick={() => setRuleDialog(rule)} />
                      <IconButton variant="destructive" icon={Trash2} title={t('common.delete')} onClick={() => deleteRule(rule)} />
                    </div>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">{t('access.rules.order')}</p>
          </Card>
        </div>

        {/* Bundles available on this server */}
        <div className="space-y-4">
          <Card>
            <CardHeader
              title={t('access.bundles.title')}
              description={t('access.bundles.subtitle')}
              action={<Button variant="secondary" size="sm" icon={Plus} onClick={() => setBundleForm({})} data-testid="add-bundle">{t('access.bundles.add')}</Button>}
            />
            {visibleBundles.length === 0 ? (
              <EmptyState compact icon={Package} title={t('access.bundles.empty')} description={t('access.bundles.emptyHint')} />
            ) : (
              <div className="divide-y divide-border">
                {visibleBundles.map((b) => (
                  <div key={b.name} className="py-2.5" data-testid={`access-bundle-${b.name}`}>
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <BundleName scope={b} className="min-w-0 text-sm" />
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-1">
                          <Badge tone={b.source === 'service' ? 'accent' : 'neutral'}>{t(`access.source.${b.source}`)}</Badge>
                          {b.is_default && <Badge tone="success">{t('clients.scopes.default')}</Badge>}
                          <span className="text-xs text-muted-foreground">{t('access.bundles.toolCount', { count: b.tools.length })}</span>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-0.5">
                        <IconButton icon={ListChecks} title={t('access.bundles.editTools')} onClick={() => setEditBundleTools(b)} disabled={!b.challenge_safe} data-testid={`bundle-tools-${b.name}`} />
                        {b.source === 'service' && (
                          <>
                            <IconButton icon={Pencil} title={t('common.edit')} onClick={() => setBundleForm(b)} />
                            <IconButton variant="destructive" icon={Trash2} title={t('common.delete')} onClick={() => deleteBundle(b)} />
                          </>
                        )}
                      </div>
                    </div>
                    {b.tools.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {b.tools.map((n) => <Badge key={n} tone="neutral" mono>{n}</Badge>)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            <p className="mt-3 border-t border-border pt-3 text-xs text-muted-foreground">
              {t('access.bundles.globalHint')}{' '}
              <Link to="/bundles" className="text-link transition-colors duration-200 hover:text-link-hover">{t('access.bundles.allBundles')}</Link>
            </p>
          </Card>
        </div>
      </div>

      {editTool && (
        <ToolScopesDialog serviceId={service.id} tool={editTool} access={access} onClose={() => setEditTool(null)}
          onSaved={async () => { toast.success(t('access.toolScopes.saved', { name: editTool.name })); await onChanged() }} />
      )}
      {editBundleTools && (
        <BundleToolsDialog scope={editBundleTools} servers={[{ serviceId: service.id, name: service.name, access }]}
          onClose={() => setEditBundleTools(null)} onSaved={onChanged} />
      )}
      {bundleForm && (
        <BundleFormDialog bundle={bundleForm.name ? bundleForm : null} fixedServiceId={service.id} onClose={() => setBundleForm(null)} onSubmit={saveBundle} />
      )}
      {ruleDialog && (
        <RuleDialog serviceId={service.id} rule={ruleDialog.id ? ruleDialog : null} access={access} subjects={subjects}
          onClose={() => setRuleDialog(null)}
          onSaved={async () => { toast.success(t('access.rules.saved')); await onChanged() }} />
      )}
    </div>
  )
}

