import { useState, useEffect, useCallback } from 'react'
import { formatDateTime } from '../utils/format'
import { useTranslation } from 'react-i18next'
import {
  Bot, Plus, RefreshCw, Check, Ban, Trash2, KeyRound, Lock, Unlock, Pencil,
} from 'lucide-react'
import { oauthApi, servicesApi } from '../services/api'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import CodeBlock from '../components/CodeBlock'
import LastChecked from '../components/LastChecked'
import clsx from 'clsx'
import { describeScope } from '../utils/scopes'
import {
  PageHeader, Button, IconButton, Badge, StatusPill, Card, CardHeader, EmptyState, Alert, LoadingBlock, Tabs,
  Table, THead, TBody, TR, TH, TD, RowActions,
  Dialog, DialogBody, DialogFooter, Field, Input, Select, Textarea, Checkbox, CheckRow,
} from '../components/ui'

const TABS = ['approved', 'pending', 'revoked']
const GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials']
const AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post']
const STATUS_TONE = { approved: 'success', pending: 'warning', revoked: 'neutral' }

function clientStatus(c) {
  if (!c.is_active) return 'revoked'
  return c.is_approved ? 'approved' : 'pending'
}

// ---------- Register trusted client ----------
function RegisterClientModal({ onClose, onCreated }) {
  const { t } = useTranslation()
  const [form, setForm] = useState({
    clientName: '', clientUri: '', redirectUris: '', grantTypes: new Set(['authorization_code', 'refresh_token']),
    authMethod: 'none', classic: false, defaultResource: '',
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [services, setServices] = useState([])
  const confidential = form.authMethod !== 'none'

  // Registered servers, offered as the default resource for classic clients
  useEffect(() => {
    let cancelled = false
    servicesApi.getAll().then((res) => { if (!cancelled) setServices(res.services || []) }).catch(() => {})
    return () => { cancelled = true }
  }, [])

  const toggleGrant = (g) => {
    const next = new Set(form.grantTypes)
    if (next.has(g)) next.delete(g)
    else next.add(g)
    setForm({ ...form, grantTypes: next })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const res = await oauthApi.clients.create({
        clientName: form.clientName.trim(),
        clientUri: form.clientUri.trim() || null,
        redirectUris: form.redirectUris.split('\n').map((x) => x.trim()).filter(Boolean),
        grantTypes: [...form.grantTypes],
        tokenEndpointAuthMethod: form.authMethod,
        requirePkce: !(confidential && form.classic),
        defaultResource: confidential && form.classic ? form.defaultResource || null : null,
      })
      onCreated(res)
    } catch (err) {
      setError(err.message || t('clients.form.createFailed'))
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog open onClose={onClose} size="xl" title={t('clients.form.title')}>
      <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col">
        <DialogBody className="space-y-5">
          {error && <Alert tone="danger">{error}</Alert>}
          <Field label={t('clients.form.clientName')} required>
            <Input type="text" value={form.clientName} onChange={(e) => setForm({ ...form, clientName: e.target.value })} required autoFocus maxLength={128} />
          </Field>
          <Field label={t('clients.form.clientUri')}>
            <Input type="url" value={form.clientUri} onChange={(e) => setForm({ ...form, clientUri: e.target.value })} placeholder="https://" mono />
          </Field>
          <Field label={t('clients.form.redirectUris')} help={t('clients.form.redirectUrisHint')}>
            <Textarea
              value={form.redirectUris}
              onChange={(e) => setForm({ ...form, redirectUris: e.target.value })}
              rows={3}
              placeholder={'http://localhost:3000/callback\nhttps://app.example.com/oauth/callback'}
              mono
            />
          </Field>
          <Field label={t('clients.form.grantTypes')}>
            <div className="flex flex-wrap gap-1.5">
              {GRANT_TYPES.map((g) => {
                const on = form.grantTypes.has(g)
                return (
                  <button
                    key={g}
                    type="button"
                    onClick={() => toggleGrant(g)}
                    aria-pressed={on}
                    className={clsx(
                      'inline-flex h-7 items-center gap-1 rounded-md border px-2 font-mono text-xs transition-colors duration-200',
                      on
                        ? 'border-primary bg-primary text-primary-foreground'
                        : 'border-border-strong bg-card text-muted-foreground hover:border-subtle-foreground hover:text-foreground',
                    )}
                  >
                    {on && <Check className="h-3 w-3" aria-hidden="true" />}{g}
                  </button>
                )
              })}
            </div>
          </Field>
          <Field label={t('clients.form.authMethod')} help={t('clients.form.authMethodHint')}>
            <Select value={form.authMethod} onChange={(e) => setForm({ ...form, authMethod: e.target.value })}>
              {AUTH_METHODS.map((m) => <option key={m} value={m}>{t(`clients.authMethod.${m}`)}</option>)}
            </Select>
          </Field>
          {confidential && (
            <div className="space-y-3 rounded-md border border-border bg-muted/40 p-4">
              <CheckRow
                checked={form.classic}
                onChange={(e) => setForm({ ...form, classic: e.target.checked })}
                label={t('clients.form.classicLabel')}
                description={t('clients.form.classicHint')}
              />
              {form.classic && (
                <Field label={t('clients.form.defaultResource')} help={t('clients.form.defaultResourceHint')}>
                  <Select value={form.defaultResource} onChange={(e) => setForm({ ...form, defaultResource: e.target.value })}>
                    <option value="">{t('clients.form.defaultResourceNone')}</option>
                    {services.map((s) => (
                      <option key={s.id} value={s.effective_audience}>{s.name} — {s.effective_audience}</option>
                    ))}
                  </Select>
                </Field>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="secondary" onClick={onClose}>{t('clients.form.cancel')}</Button>
          <Button type="submit" variant="primary" icon={Plus} loading={isLoading} disabled={!form.clientName.trim() || form.grantTypes.size === 0}>
            {isLoading ? t('clients.form.submitting') : t('clients.form.submit')}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  )
}

// ---------- Secret shown once ----------
function SecretModal({ client, onClose }) {
  const { t } = useTranslation()
  return (
    <Dialog open onClose={onClose} size="lg" title={t('clients.secret.title')}>
      <DialogBody className="space-y-4">
        <p className="text-sm text-muted-foreground">{t('clients.secret.body', { name: client.client_name })}</p>
        <CodeBlock title={t('clients.secret.clientId')} value={client.client_id} sensitive />
        {client.client_secret ? (
          <>
            <CodeBlock title={t('clients.secret.clientSecret')} value={client.client_secret} sensitive />
            <Alert tone="warning">{t('clients.secret.oneTime')}</Alert>
          </>
        ) : (
          <p className="text-xs text-muted-foreground">{t('clients.secret.publicClient')}</p>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="primary" onClick={onClose}>{t('clients.secret.done')}</Button>
      </DialogFooter>
    </Dialog>
  )
}

// ---------- Scopes ----------
function ScopesSection() {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirmDelete } = useConfirm()
  const [scopes, setScopes] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [editing, setEditing] = useState(null)   // {name, description, isDefault, isNew}
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await oauthApi.scopes.list()
      setScopes(res.scopes || [])
    } catch (err) {
      toast.error(err.message || t('clients.loadFailed'))
    } finally {
      setIsLoading(false)
    }
  }, [toast, t])

  useEffect(() => { load() }, [load])

  const save = async () => {
    if (!editing?.name.trim()) return
    setSaving(true)
    try {
      await oauthApi.scopes.upsert(editing.name.trim(), { description: editing.description, isDefault: editing.isDefault })
      toast.success(t('clients.scopes.saved'))
      setEditing(null)
      await load()
    } catch (err) {
      toast.error(err.message || t('clients.scopes.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  const remove = async (name) => {
    const ok = await confirmDelete(t('clients.scopes.deleteTarget', { name }))
    if (!ok) return
    try {
      await oauthApi.scopes.delete(name)
      toast.success(t('clients.scopes.deleted'))
      await load()
    } catch (err) {
      toast.error(err.message || t('clients.scopes.deleteFailed'))
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('clients.scopes.title')}
        description={t('clients.scopes.subtitle')}
        action={
          <Button variant="secondary" size="sm" icon={Plus} onClick={() => setEditing({ name: '', description: '', isDefault: false, isNew: true })}>
            {t('clients.scopes.add')}
          </Button>
        }
      />

      {editing && (
        <div className="mb-4 space-y-3 rounded-md border border-border bg-muted/40 p-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Input
              type="text"
              size="sm"
              value={editing.name}
              onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              placeholder={t('clients.scopes.namePlaceholder')}
              disabled={!editing.isNew}
              pattern="[^\s]+"
              autoFocus
              mono
            />
            <Input
              type="text"
              size="sm"
              value={editing.description || ''}
              onChange={(e) => setEditing({ ...editing, description: e.target.value })}
              placeholder={t('clients.scopes.descriptionPlaceholder')}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <Checkbox checked={editing.isDefault} onChange={(e) => setEditing({ ...editing, isDefault: e.target.checked })} />
              {t('clients.scopes.isDefault')}
            </label>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" onClick={() => setEditing(null)}>{t('clients.scopes.cancel')}</Button>
              <Button variant="primary" size="sm" icon={Check} onClick={save} loading={saving} disabled={!editing.name.trim()}>
                {t('clients.scopes.save')}
              </Button>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <LoadingBlock className="py-6" size="sm" />
      ) : scopes.length === 0 ? (
        <EmptyState compact title={t('clients.scopes.empty')} />
      ) : (
        <div className="divide-y divide-border">
          {scopes.map((s) => (
            <div key={s.name} className="group flex items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <p className="flex items-center gap-2 font-mono text-xs font-medium text-foreground">
                  {s.name}
                  {s.is_default && <Badge tone="success">{t('clients.scopes.default')}</Badge>}
                </p>
                <p className="truncate text-xs text-muted-foreground">{describeScope(t, s.name, s.description) || t('clients.scopes.noDescription')}</p>
              </div>
              <RowActions>
                <IconButton
                  icon={Pencil}
                  onClick={() => setEditing({ name: s.name, description: s.description || '', isDefault: !!s.is_default, isNew: false })}
                  title={t('clients.scopes.edit')}
                />
                <IconButton variant="destructive" icon={Trash2} onClick={() => remove(s.name)} title={t('clients.scopes.delete')} />
              </RowActions>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

// ---------- Signing keys ----------
function KeysSection() {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirm } = useConfirm()
  const [keys, setKeys] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [rotating, setRotating] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await oauthApi.keys.list()
      setKeys(res.keys || [])
    } catch (err) {
      toast.error(err.message || t('clients.loadFailed'))
    } finally {
      setIsLoading(false)
    }
  }, [toast, t])

  useEffect(() => { load() }, [load])

  const rotate = async () => {
    const ok = await confirm({
      title: t('clients.keys.rotateConfirmTitle'),
      message: t('clients.keys.rotateConfirmBody'),
      confirmText: t('clients.keys.rotate'),
      type: 'warning',
    })
    if (!ok) return
    setRotating(true)
    try {
      await oauthApi.keys.rotate()
      toast.success(t('clients.keys.rotated'))
      await load()
    } catch (err) {
      toast.error(err.message || t('clients.keys.rotateFailed'))
    } finally {
      setRotating(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title={t('clients.keys.title')}
        description={t('clients.keys.subtitle')}
        action={
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={rotate} loading={rotating}>
            {rotating ? t('clients.keys.rotating') : t('clients.keys.rotate')}
          </Button>
        }
      />
      {isLoading ? (
        <LoadingBlock className="py-6" size="sm" />
      ) : keys.length === 0 ? (
        <EmptyState compact icon={KeyRound} title={t('clients.keys.empty')} />
      ) : (
        <div className="divide-y divide-border">
          {keys.map((k) => (
            <div key={k.kid} className="flex items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-medium text-foreground">{k.kid}</p>
                <p className="text-xs text-muted-foreground tabular-nums">{k.alg} · {t('clients.keys.created', { date: k.created_at ? formatDateTime(k.created_at) : '—' })}</p>
              </div>
              <StatusPill tone={k.is_active ? 'success' : 'neutral'}>
                {k.is_active ? t('clients.keys.active') : t('clients.keys.inactive')}
              </StatusPill>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

// ---------- Page ----------
export default function OAuthClientsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirmDelete, confirm } = useConfirm()
  const [tab, setTab] = useState('approved')
  const [clients, setClients] = useState([])
  const [counts, setCounts] = useState({})
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showRegister, setShowRegister] = useState(false)
  const [secretClient, setSecretClient] = useState(null)
  const [busy, setBusy] = useState(null)

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setIsLoading(true)
    setError(null)
    try {
      const res = await oauthApi.clients.list('all')
      const all = res.clients || []
      setClients(all)
      setCounts(all.reduce((acc, c) => { const s = clientStatus(c); acc[s] = (acc[s] || 0) + 1; return acc }, {}))
    } catch (err) {
      setError(err.message || t('clients.loadFailed'))
    } finally {
      if (!silent) setIsLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const visible = clients.filter((c) => clientStatus(c) === tab)

  const run = async (client, fn, successMsg) => {
    setBusy(client.client_id)
    try {
      const r = await fn()
      toast.success(successMsg(r))
      await load({ silent: true })
    } catch (err) {
      toast.error(err.message || t('clients.actionFailed'))
    } finally {
      setBusy(null)
    }
  }

  const approve = (c) => run(c, () => oauthApi.clients.approve(c.client_id), () => t('clients.toast.approved', { name: c.client_name }))
  const revoke = async (c) => {
    const ok = await confirm({
      title: t('clients.revokeConfirmTitle'),
      message: t('clients.revokeConfirmBody', { name: c.client_name }),
      confirmText: t('clients.revoke'),
      type: 'revoke',
    })
    if (!ok) return
    run(c, () => oauthApi.clients.revoke(c.client_id), (r) => t('clients.toast.revoked', { name: c.client_name, n: r?.tokens_revoked ?? 0 }))
  }
  const remove = async (c) => {
    const ok = await confirmDelete(t('clients.deleteTarget', { name: c.client_name }))
    if (!ok) return
    run(c, () => oauthApi.clients.delete(c.client_id), () => t('clients.toast.deleted', { name: c.client_name }))
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('clients.title')}
        description={t('clients.subtitle')}
        actions={
          <>
            <IconButton
              variant="secondary"
              icon={RefreshCw}
              title={t('clients.refresh')}
              onClick={() => load()}
              disabled={isLoading}
              className={clsx(isLoading && 'animate-spin')}
            />
            <Button variant="primary" icon={Plus} onClick={() => setShowRegister(true)}>
              {t('clients.register')}
            </Button>
          </>
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}

      <div className="space-y-4">
        <Tabs
          value={tab}
          onChange={setTab}
          items={TABS.map((k) => ({ key: k, label: t(`clients.tabs.${k}`), count: counts[k] || 0 }))}
        />

        {isLoading ? (
          <Card padding="none"><LoadingBlock /></Card>
        ) : error ? null : visible.length === 0 ? (
          <Card padding="none">
            <EmptyState
              icon={Bot}
              title={t(`clients.empty.${tab}`)}
              description={tab === 'approved' ? t('clients.emptyHint') : undefined}
            />
          </Card>
        ) : (
          <Table>
            <THead>
              <TR hover={false} group={false}>
                <TH>{t('clients.col.name')}</TH>
                <TH>{t('clients.col.createdVia')}</TH>
                <TH>{t('clients.col.grantTypes')}</TH>
                <TH className="hidden 2xl:table-cell">{t('clients.col.redirectUris')}</TH>
                <TH className="hidden lg:table-cell">{t('clients.col.lastUsed')}</TH>
                <TH>{t('clients.col.status')}</TH>
                <TH align="right"><span className="sr-only">{t('clients.col.actions')}</span></TH>
              </TR>
            </THead>
            <TBody>
              {visible.map((c) => {
                const status = clientStatus(c)
                const isSystem = c.created_via === 'system'
                const isBusy = busy === c.client_id
                return (
                  <TR key={c.client_id}>
                    <TD className="max-w-xs">
                      <div className="flex items-center gap-3">
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-muted text-muted-foreground">
                          {c.logo_uri ? <img src={c.logo_uri} alt="" className="h-full w-full object-cover" /> : <Bot className="h-4 w-4" aria-hidden="true" />}
                        </span>
                        <div className="min-w-0">
                          <p className="flex items-center gap-1.5 truncate font-medium text-foreground">
                            <span className="truncate">{c.client_name}</span>
                            {c.is_confidential
                              ? <Lock className="h-3 w-3 shrink-0 text-subtle-foreground" title={t('clients.confidential')} />
                              : <Unlock className="h-3 w-3 shrink-0 text-subtle-foreground" title={t('clients.public')} />}
                          </p>
                          <p className="truncate font-mono text-xs text-muted-foreground" title={c.client_id}>{c.client_id}</p>
                          {c.client_uri && (
                            <a href={c.client_uri} target="_blank" rel="noreferrer" className="block truncate text-xs text-link transition-colors duration-200 hover:text-link-hover">{c.client_uri}</a>
                          )}
                        </div>
                      </div>
                    </TD>
                    <TD>
                      <Badge tone={c.created_via === 'dcr' ? 'warning' : isSystem ? 'neutral' : 'success'}>
                        {t(`clients.via.${c.created_via}`, c.created_via)}
                      </Badge>
                    </TD>
                    <TD>
                      <div className="flex flex-wrap gap-1">
                        {(c.grant_types || []).map((g) => <Badge key={g} tone="neutral" mono>{g}</Badge>)}
                      </div>
                    </TD>
                    <TD className="hidden max-w-[16rem] 2xl:table-cell">
                      {(c.redirect_uris || []).length === 0 ? (
                        <span className="text-xs text-subtle-foreground">{t('clients.noRedirect')}</span>
                      ) : (
                        <div className="space-y-0.5">
                          {c.redirect_uris.slice(0, 2).map((u) => <p key={u} className="truncate font-mono text-xs text-muted-foreground" title={u}>{u}</p>)}
                          {c.redirect_uris.length > 2 && <p className="text-xs text-subtle-foreground tabular-nums">+{c.redirect_uris.length - 2}</p>}
                        </div>
                      )}
                    </TD>
                    <TD className="hidden whitespace-nowrap text-xs text-muted-foreground lg:table-cell">
                      {c.last_used_at ? <LastChecked value={c.last_used_at} /> : <span className="text-subtle-foreground">{t('clients.neverUsed')}</span>}
                    </TD>
                    <TD>
                      <StatusPill tone={STATUS_TONE[status]} pulse={status === 'pending'}>
                        {t(`clients.status.${status}`)}
                      </StatusPill>
                    </TD>
                    <TD align="right">
                      <RowActions always={status === 'pending' || isBusy}>
                        {status !== 'approved' && (
                          <Button variant="primary" size="xs" icon={Check} onClick={() => approve(c)} disabled={isBusy} title={t('clients.approve')}>
                            {t('clients.approve')}
                          </Button>
                        )}
                        {status !== 'revoked' && !isSystem && (
                          <IconButton icon={Ban} onClick={() => revoke(c)} disabled={isBusy} title={t('clients.revoke')} />
                        )}
                        {!isSystem && (
                          <IconButton variant="destructive" icon={Trash2} onClick={() => remove(c)} disabled={isBusy} title={t('clients.delete')} />
                        )}
                        {isBusy && <RefreshCw className="ml-1 h-4 w-4 animate-spin text-subtle-foreground" aria-hidden="true" />}
                      </RowActions>
                    </TD>
                  </TR>
                )
              })}
            </TBody>
          </Table>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ScopesSection />
        <KeysSection />
      </div>

      {showRegister && (
        <RegisterClientModal
          onClose={() => setShowRegister(false)}
          onCreated={(res) => {
            setShowRegister(false)
            setSecretClient(res)
            toast.success(t('clients.toast.created', { name: res.client_name }))
            load({ silent: true })
          }}
        />
      )}
      {secretClient && <SecretModal client={secretClient} onClose={() => setSecretClient(null)} />}
    </div>
  )
}
