import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check } from 'lucide-react'
import { accessApi } from '../../services/api'
import {
  ALL_TOOLS, assignableScopes, explicitChallenge, isScopeToken, ruleBody, ruleForm, ruleFormError, toolScopeNames, toolScopesBody,
} from '../../utils/access'
import {
  Dialog, DialogBody, DialogFooter, Button, Badge, Checkbox, Radio, Field, Input, Select, Alert, SegmentedControl, Help,
} from '../ui'

/** A bundle's name as people read it: its title, with the scope name beside it */
export function BundleName({ scope, className }) {
  return (
    <span className={className}>
      {scope.title ? (
        <><span className="font-medium text-foreground">{scope.title}</span> <span className="break-all font-mono text-[11px] text-muted-foreground">{scope.name}</span></>
      ) : (
        <span className="break-all font-mono text-xs font-medium text-foreground">{scope.name}</span>
      )}
    </span>
  )
}

/** Which bundles (scopes) one tool is in, and which of them a step-up challenge names. */
export function ToolScopesDialog({ serviceId, tool, access, onClose, onSaved }) {
  const { t } = useTranslation()
  const scopes = access.scopes
  const [selected, setSelected] = useState(() => new Set(toolScopeNames(tool)))
  const [challenge, setChallenge] = useState(() => explicitChallenge(tool) || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const safe = new Set(assignableScopes(access).map((s) => s.name))

  const toggle = (name) => setSelected((prev) => {
    const next = new Set(prev)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    return next
  })

  const chosen = scopes.filter((s) => selected.has(s.name))
  const save = async () => {
    setSaving(true)
    setError('')
    try {
      await accessApi.setToolScopes(serviceId, tool.id, toolScopesBody(tool, [...selected], challenge || null))
      await onSaved?.()
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onClose={onClose} size="lg" title={t('access.toolScopes.title', { name: tool.name })} description={t('access.toolScopes.subtitle')}>
      <DialogBody className="space-y-5">
        {error && <Alert tone="danger">{error}</Alert>}
        <div className="divide-y divide-border rounded-md border border-border">
          {scopes.map((s) => {
            const disabled = !safe.has(s.name) && !selected.has(s.name)
            return (
              <label key={s.name} className={`flex items-start gap-3 px-3 py-2.5 ${disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:bg-muted/60'}`}>
                <Checkbox className="mt-0.5" checked={selected.has(s.name)} disabled={disabled} onChange={() => toggle(s.name)} data-testid={`tool-scope-${s.name}`} />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <BundleName scope={s} />
                    <Badge tone={s.source === 'service' ? 'accent' : 'neutral'}>{t(`access.source.${s.source}`)}</Badge>
                  </span>
                  {s.description && <span className="mt-0.5 block text-xs text-muted-foreground">{s.description}</span>}
                  {disabled && <span className="mt-0.5 block text-xs text-warning">{t('access.toolScopes.unsafe')}</span>}
                </span>
              </label>
            )
          })}
        </div>
        {chosen.length === 0 ? (
          <Help>{t(access.unscoped_tools === 'require' ? 'access.toolScopes.noneRequire' : 'access.toolScopes.noneAllow')}</Help>
        ) : (
          <Field label={t('access.toolScopes.challengeLabel')} help={t('access.toolScopes.challengeHelp')}>
            <div className="space-y-1.5">
              <label className="flex cursor-pointer items-center gap-2 text-sm">
                <Radio name="challenge" checked={!challenge || !selected.has(challenge)} onChange={() => setChallenge('')} />
                {t('access.toolScopes.challengeAuto')}
              </label>
              {chosen.map((s) => (
                <label key={s.name} className="flex cursor-pointer items-center gap-2 text-sm">
                  <Radio name="challenge" checked={challenge === s.name} onChange={() => setChallenge(s.name)} />
                  <span className="break-all font-mono text-xs">{s.name}</span>
                </label>
              ))}
            </div>
          </Field>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant="primary" size="sm" icon={Check} loading={saving} onClick={save}>{t('common.save')}</Button>
      </DialogFooter>
    </Dialog>
  )
}

/**
 * Create or edit a deny / "only these tools" rule. `subjects` = subjectOptions(...) (pat / client / user / group
 * lists); a subject the lists no longer hold (a revoked token) is kept as its id so an edit does not drop it.
 */
export function RuleDialog({ serviceId, rule, access, subjects, onClose, onSaved }) {
  const { t } = useTranslation()
  const [form, setForm] = useState(() => ruleForm(rule))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [touched, setTouched] = useState(false)
  const tools = access.tools.filter((tl) => !tl.removed || form.tools.includes(tl.name))
  const options = useMemo(() => {
    const list = subjects[form.kind] || []
    if (form.subjectId && !list.some((o) => o.id === form.subjectId)) {
      return [{ id: form.subjectId, label: rule?.subject?.label || form.subjectId, hint: '' }, ...list]
    }
    return list
  }, [subjects, form.kind, form.subjectId, rule])
  const problem = ruleFormError(form)
  const all = form.tools.includes(ALL_TOOLS)

  const set = (patch) => setForm((f) => ({ ...f, ...patch }))
  const toggleTool = (name) => set({ tools: form.tools.includes(name) ? form.tools.filter((n) => n !== name) : [...form.tools.filter((n) => n !== ALL_TOOLS), name] })

  const save = async () => {
    setTouched(true)
    if (problem) return
    setSaving(true)
    setError('')
    try {
      if (rule) await accessApi.updateRule(serviceId, rule.id, ruleBody(form))
      else await accessApi.createRule(serviceId, ruleBody(form))
      await onSaved?.()
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onClose={onClose} size="lg" title={t(rule ? 'access.rules.editTitle' : 'access.rules.addTitle')} description={t('access.rules.dialogSubtitle')}>
      <DialogBody className="space-y-5">
        {error && <Alert tone="danger">{error}</Alert>}
        <Field label={t('access.rules.effectLabel')} help={t(`access.rules.effectHelp.${form.effect}`)}>
          <SegmentedControl
            value={form.effect}
            onChange={(effect) => set({ effect, tools: effect === 'only' ? form.tools.filter((n) => n !== ALL_TOOLS) : form.tools })}
            items={[{ key: 'deny', label: t('access.rules.effect.deny') }, { key: 'only', label: t('access.rules.effect.only') }]}
          />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[10rem_1fr]">
          <Field label={t('access.rules.subjectKindLabel')}>
            <Select value={form.kind} onChange={(e) => set({ kind: e.target.value, subjectId: '' })} data-testid="rule-subject-kind">
              {['pat', 'client', 'user', 'group'].map((k) => <option key={k} value={k}>{t(`access.subject.${k}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('access.rules.subjectLabel')} help={t(`access.rules.subjectHelp.${form.kind}`)} error={touched && problem === 'subject' ? t('access.rules.errors.subject') : null}>
            <Select value={form.subjectId} onChange={(e) => set({ subjectId: e.target.value })} invalid={touched && problem === 'subject'} data-testid="rule-subject">
              <option value="">{options.length ? t('access.rules.chooseSubject') : t(`access.rules.noSubjects.${form.kind}`)}</option>
              {options.map((o) => <option key={o.id} value={o.id}>{o.hint && o.hint !== o.label ? `${o.label} (${o.hint})` : o.label}</option>)}
            </Select>
          </Field>
        </div>
        <Field
          label={t('access.rules.toolsLabel')}
          error={touched && ['noTools', 'onlyAllTools', 'wildcardNotAlone'].includes(problem) ? t(`access.rules.errors.${problem}`) : null}
        >
          <div className="divide-y divide-border rounded-md border border-border">
            {form.effect === 'deny' && (
              <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/60">
                <Checkbox checked={all} onChange={() => set({ tools: all ? [] : [ALL_TOOLS] })} data-testid="rule-all-tools" />
                <span className="text-sm font-medium text-foreground">{t('access.rules.allTools')}</span>
              </label>
            )}
            {tools.map((tool) => (
              <label key={tool.id} className={`flex items-center gap-3 px-3 py-2 ${all ? 'opacity-50' : 'cursor-pointer hover:bg-muted/60'}`}>
                <Checkbox checked={!all && form.tools.includes(tool.name)} disabled={all} onChange={() => toggleTool(tool.name)} data-testid={`rule-tool-${tool.name}`} />
                <span className="min-w-0 break-all font-mono text-xs text-foreground">{tool.name}</span>
                {tool.state !== 'approved' && <Badge tone={tool.state === 'pending' ? 'warning' : 'danger'}>{t(`services.toolPin.state.${tool.state}`)}</Badge>}
              </label>
            ))}
          </div>
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label={t('access.rules.noteLabel')}>
            <Input value={form.note} maxLength={256} onChange={(e) => set({ note: e.target.value })} placeholder={t('access.rules.notePlaceholder')} />
          </Field>
          <Field
            label={t('access.rules.expiresLabel')}
            help={t('access.rules.expiresHelp')}
            error={touched && ['expiresInPast', 'expiresInvalid'].includes(problem) ? t(`access.rules.errors.${problem}`) : null}
          >
            <Input type="datetime-local" value={form.expires} onChange={(e) => set({ expires: e.target.value })} invalid={touched && ['expiresInPast', 'expiresInvalid'].includes(problem)} data-testid="rule-expires" />
          </Field>
        </div>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant="primary" size="sm" icon={Check} loading={saving} onClick={save} data-testid="rule-save">{t('common.save')}</Button>
      </DialogFooter>
    </Dialog>
  )
}

/**
 * Create or edit a bundle = a scope with a title. `servers` (optional) lets a new bundle be made for one server
 * only (a server's own scope) instead of for all servers (a global scope); `fixedServiceId` pins it to one.
 */
export function BundleFormDialog({ bundle, servers = [], fixedServiceId = null, onClose, onSubmit }) {
  const { t } = useTranslation()
  const isNew = !bundle
  const [form, setForm] = useState(() => ({
    name: bundle?.name || '',
    title: bundle?.title || '',
    description: bundle?.description || '',
    isDefault: !!bundle?.is_default,
    serviceId: bundle ? (bundle.service_id || '') : (fixedServiceId || ''),
  }))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const set = (patch) => setForm((f) => ({ ...f, ...patch }))
  const name = form.name.trim()
  const nameInvalid = name !== '' && !isScopeToken(name)

  const save = async () => {
    if (!name || nameInvalid) return
    setSaving(true)
    setError('')
    try {
      await onSubmit({ ...form, name, title: form.title.trim() })
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog onClose={onClose} title={t(isNew ? 'access.bundleForm.addTitle' : 'access.bundleForm.editTitle')} description={t('access.bundleForm.subtitle')}>
      <DialogBody className="space-y-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <Field label={t('access.bundleForm.titleLabel')} help={t('access.bundleForm.titleHelp')}>
          <Input value={form.title} maxLength={128} onChange={(e) => set({ title: e.target.value })} placeholder={t('access.bundleForm.titlePlaceholder')} autoFocus data-testid="bundle-title" />
        </Field>
        <Field
          label={t('access.bundleForm.nameLabel')}
          required
          help={t('access.bundleForm.nameHelp')}
          error={nameInvalid ? t('access.bundleForm.nameInvalid') : null}
        >
          <Input value={form.name} onChange={(e) => set({ name: e.target.value })} disabled={!isNew} mono invalid={nameInvalid} placeholder={t('access.bundleForm.namePlaceholder')} data-testid="bundle-name" />
        </Field>
        <Field label={t('access.bundleForm.descriptionLabel')}>
          <Input value={form.description} onChange={(e) => set({ description: e.target.value })} placeholder={t('access.bundleForm.descriptionPlaceholder')} />
        </Field>
        {isNew && !fixedServiceId && servers.length > 0 && (
          <Field label={t('access.bundleForm.whereLabel')} help={t('access.bundleForm.whereHelp')}>
            <Select value={form.serviceId} onChange={(e) => set({ serviceId: e.target.value })} data-testid="bundle-where">
              <option value="">{t('access.bundleForm.allServers')}</option>
              {servers.map((s) => <option key={s.id} value={s.id}>{t('access.bundleForm.onlyServer', { name: s.name })}</option>)}
            </Select>
          </Field>
        )}
        <label className="flex cursor-pointer items-start gap-2 text-sm text-foreground">
          <Checkbox className="mt-0.5" checked={form.isDefault} onChange={(e) => set({ isDefault: e.target.checked })} />
          <span>
            {t('access.bundleForm.defaultLabel')}
            <span className="block text-xs text-muted-foreground">{t('access.bundleForm.defaultHelp')}</span>
          </span>
        </label>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant="primary" size="sm" icon={Check} loading={saving} disabled={!name || nameInvalid} onClick={save} data-testid="bundle-save">{t('common.save')}</Button>
      </DialogFooter>
    </Dialog>
  )
}
