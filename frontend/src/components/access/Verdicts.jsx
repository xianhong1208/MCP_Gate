import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { FlaskConical, ShieldAlert, Wrench } from 'lucide-react'
import { accessApi } from '../../services/api'
import { enforcement, subjectLabel, subjectOptions } from '../../utils/access'
import { DECISIONS, WHAT_IF_KINDS, compareLive, sortVerdicts, verdictReason, whatIfForm, whatIfParams } from '../../utils/accessCheck'
import { Alert, Badge, Button, Card, CardHeader, EmptyState, Field, Select, Spinner } from '../ui'

const DECISION_TONE = { allowed: 'success', needs_scope: 'warning', hidden: 'neutral' }
const LIVE_TONE = { listed: 'neutral', notListed: 'warning', probeOnly: 'neutral', exposed: 'danger', unverified: 'neutral' }

/** Allowed / needs a bundle / hidden counts of a check */
export function VerdictCounts({ counts }) {
  const { t } = useTranslation()
  return (
    <span className="flex flex-wrap gap-1" data-testid="verdict-counts">
      {DECISIONS.map((d) => (
        <Badge key={d} tone={counts?.[d] ? DECISION_TONE[d] : 'neutral'}>{t(`access.check.count.${d}`, { count: counts?.[d] || 0 })}</Badge>
      ))}
    </span>
  )
}

/**
 * MCP Gate's verdict per tool for one check (GET /api/services/{id}/access/check). `compare` (compareLive) adds what
 * the server itself listed; `serviceId` links the rules to the server's Access tab.
 */
export function VerdictList({ check, compare = null, serviceId = null }) {
  const { t } = useTranslation()
  const tools = sortVerdicts(check?.tools)
  if (tools.length === 0) {
    return <EmptyState compact icon={Wrench} title={t('access.tools.empty')} description={t('services.common.refreshServerHint')} />
  }
  return (
    <div className="divide-y divide-border" data-testid="verdict-list">
      {tools.map((tool) => {
        const why = verdictReason(tool, check.scopes, subjectLabel)
        const live = compare?.status[tool.name]
        return (
          <div key={tool.id || tool.name} className="py-2" data-testid={`verdict-${tool.name}`} data-decision={tool.decision} data-live={live || ''}>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="min-w-0 break-all font-mono text-xs font-medium text-foreground">{tool.name}</span>
              <Badge tone={DECISION_TONE[tool.decision] || 'neutral'}>{t(`access.check.decision.${tool.decision}`)}</Badge>
              {live && live !== 'hiddenOk' && (
                <Badge tone={LIVE_TONE[live]} title={t(`access.check.live.${live}Hint`)}>{t(`access.check.live.${live}`)}</Badge>
              )}
            </div>
            <p className="mt-0.5 break-words text-xs text-muted-foreground">
              {t(`access.check.reason.${why.key}`, why.values)}
              {serviceId && (tool.rules || []).length > 0 && (
                <> · <Link to={`/services/${encodeURIComponent(serviceId)}?tab=access`} className="text-link transition-colors duration-200 hover:text-link-hover">{t('access.check.seeRules')}</Link></>
              )}
            </p>
          </div>
        )
      })}
    </div>
  )
}

/**
 * The live list against the verdict: a warning naming the tools the server listed although MCP Gate hides them from
 * this token (rules not enforced) or did not list although the token may call them; otherwise a note on why the
 * server's own list may show more (MCP Gate's inspect copy of a token sees every tool on a server with the middleware).
 */
export function LiveComparison({ compare }) {
  const { t } = useTranslation()
  if (!compare) return null
  if (compare.exposed.length || compare.notListed.length) {
    return (
      <div className="mb-2" data-testid="live-disagree">
        <Alert tone="warning" icon={ShieldAlert} title={t('access.check.disagree.title')}>
          {compare.exposed.length > 0 && <p>{t('access.check.disagree.exposed', { count: compare.exposed.length, list: compare.exposed.join(', ') })}</p>}
          {compare.notListed.length > 0 && <p>{t('access.check.disagree.notListed', { count: compare.notListed.length, list: compare.notListed.join(', ') })}</p>}
        </Alert>
      </div>
    )
  }
  const probeOnly = Object.values(compare.status).filter((s) => s === 'probeOnly').length
  return (
    <p className="mb-2 text-xs text-muted-foreground" data-testid="live-agree">
      {probeOnly > 0 ? t('access.check.agree.probeOnly', { count: probeOnly }) : t('access.check.agree.same')}
    </p>
  )
}

/**
 * Loads a check (GET /api/services/{id}/access/check). `params` = its query (null: nothing to check); a new `nonce`
 * asks again with the same query (after a rule or a refresh changed the answer).
 */
export function useAccessCheck(serviceId, params, nonce = 0) {
  const key = params ? JSON.stringify([params, nonce]) : ''
  const [state, setState] = useState({ key: '', check: null, error: '' })
  useEffect(() => {
    if (!serviceId || !key) return undefined
    let cancelled = false
    accessApi.check(serviceId, JSON.parse(key)[0])
      .then((check) => { if (!cancelled) setState({ key, check, error: '' }) })
      .catch((err) => { if (!cancelled) setState({ key, check: null, error: err.message }) })
    return () => { cancelled = true }
  }, [serviceId, key])
  const current = key !== '' && state.key === key
  return { check: current ? state.check : null, error: current ? state.error : '', loading: key !== '' && !current }
}

/**
 * The Access tab's what-if form: pick a personal token, a client, a user or "a member of" a group (users and group
 * members optionally through a client), add scopes, and see the verdict per tool. Nothing is issued or stored.
 */
export function WhatIfCard({ serviceId, access, tokens, lists }) {
  const { t } = useTranslation()
  const [form, setForm] = useState(() => whatIfForm())
  const [asked, setAsked] = useState({ params: null, n: 0 })
  const subjects = useMemo(() => subjectOptions({ tokens, ...lists }), [tokens, lists])
  const { check, error, loading } = useAccessCheck(serviceId, asked.params, asked.n)
  // A rule or bundle changed on the tab: ask again for the shown subject
  useEffect(() => { setAsked((a) => (a.params ? { ...a, n: a.n + 1 } : a)) }, [access])
  const set = (patch) => setForm((f) => ({ ...f, ...patch }))
  const toggleScope = (name) => set({ scopes: form.scopes.includes(name) ? form.scopes.filter((s) => s !== name) : [...form.scopes, name] })
  const params = whatIfParams(form)
  const options = subjects[form.kind] || []
  const pat = form.kind === 'pat' ? options.find((o) => o.id === form.subjectId) : null
  const patScopes = pat ? (tokens.find((tk) => tk.jti === pat.id)?.scopes || []) : []
  const scopes = access.scopes.filter((s) => !patScopes.includes(s.name))

  return (
    <Card data-testid="what-if">
      <CardHeader title={t('access.whatIf.title')} description={t('access.whatIf.subtitle')} />
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[10rem_1fr]">
          <Field label={t('access.whatIf.kindLabel')}>
            <Select value={form.kind} onChange={(e) => setForm(whatIfForm(e.target.value))} data-testid="what-if-kind">
              {WHAT_IF_KINDS.map((k) => <option key={k} value={k}>{t(`access.whatIf.kind.${k}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('access.whatIf.subjectLabel')} help={t(`access.whatIf.subjectHelp.${form.kind}`)}>
            <Select value={form.subjectId} onChange={(e) => set({ subjectId: e.target.value })} data-testid="what-if-subject">
              <option value="">{options.length ? t('access.rules.chooseSubject') : t(`access.rules.noSubjects.${form.kind}`)}</option>
              {options.map((o) => <option key={o.id} value={o.id}>{o.hint && o.hint !== o.label ? `${o.label} (${o.hint})` : o.label}</option>)}
            </Select>
          </Field>
        </div>
        {(form.kind === 'user' || form.kind === 'group') && (
          <Field label={t('access.whatIf.clientLabel')} help={t('access.whatIf.clientHelp')}>
            <Select value={form.clientId} onChange={(e) => set({ clientId: e.target.value })} data-testid="what-if-client">
              <option value="">{t('access.whatIf.anyClient')}</option>
              {subjects.client.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </Select>
          </Field>
        )}
        <Field label={t(form.kind === 'pat' ? 'access.whatIf.addScopesLabel' : 'access.whatIf.scopesLabel')}
          help={form.kind === 'pat' ? (patScopes.length ? t('access.whatIf.patScopes', { scopes: patScopes.join(', ') }) : t('access.whatIf.patScopesHelp')) : t('access.whatIf.scopesHelp')}>
          <div className="flex flex-wrap gap-1.5" data-testid="what-if-scopes">
            {scopes.length === 0 && <span className="text-xs text-subtle-foreground">{t('access.whatIf.noScopes')}</span>}
            {scopes.map((s) => {
              const on = form.scopes.includes(s.name)
              return (
                <button key={s.name} type="button" onClick={() => toggleScope(s.name)} aria-pressed={on} title={s.title || s.description || ''}
                  className={`max-w-full break-all rounded-md border px-2 py-1 font-mono text-[11px] transition-colors duration-150 ${on ? 'border-primary bg-primary-soft text-primary-soft-foreground' : 'border-border bg-muted/40 text-muted-foreground hover:text-foreground'}`}
                  data-testid={`what-if-scope-${s.name}`}>
                  {on ? '✓ ' : '+ '}{s.name}
                </button>
              )
            })}
          </div>
        </Field>
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" size="sm" icon={FlaskConical} disabled={!params} onClick={() => setAsked((a) => ({ params, n: a.n + 1 }))} data-testid="what-if-run">{t('access.whatIf.run')}</Button>
          <span className="text-xs text-muted-foreground">{t('access.whatIf.nothingIssued')}</span>
        </div>
        {asked.params && (
          <div className="border-t border-border pt-3" data-testid="what-if-result">
            {loading && <Spinner />}
            {error && <Alert tone="danger">{error}</Alert>}
            {check && (
              <>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <p className="min-w-0 break-words text-sm font-medium text-foreground">{whatIfTitle(t, check)}</p>
                  <VerdictCounts counts={check.counts} />
                </div>
                {check.scopes.length > 0 && <p className="mb-1 break-words text-xs text-muted-foreground">{t('access.whatIf.withScopes', { scopes: check.scopes.join(', ') })}</p>}
                <VerdictList check={check} />
              </>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}

function whatIfTitle(t, check) {
  const s = check.subject
  if (s.token) return t('access.whatIf.resultToken', { name: s.token.label || s.token.jti.slice(0, 8) })
  const through = s.client && (s.user || s.group) ? t('access.whatIf.through', { client: s.client.label || s.client.id }) : ''
  if (s.group) return t('access.whatIf.resultGroup', { name: s.group.label || s.group.id, through })
  if (s.user) return t('access.whatIf.resultUser', { name: s.user.label || s.user.id, through })
  return t('access.whatIf.resultClient', { name: s.client?.label || s.client?.id })
}

/**
 * "Inspect as" a token, on the service page: MCP Gate's verdict per tool for it, and once the tools list was
 * refreshed as that token (`live` = { jti, names }), how the server's own answer compares. `nonce` changes after a
 * refresh so the verdict is asked again.
 */
export function InspectVerdicts({ serviceId, jti, live, policyStatus, nonce }) {
  const { t } = useTranslation()
  const { check, error, loading } = useAccessCheck(serviceId, jti ? { jti } : null, nonce)
  const compare = useMemo(() => (check && live && live.jti === jti
    ? compareLive(check, live.names, enforcement(policyStatus)?.key || null) : null), [check, live, jti, policyStatus])
  if (!jti) return null
  return (
    <div className="mb-3 rounded-lg border border-border px-2.5 py-2" data-testid="inspect-verdicts">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-subtle-foreground">{t('access.check.inspectTitle')}</span>
        {check && <VerdictCounts counts={check.counts} />}
      </div>
      {loading && <Spinner size="sm" />}
      {error && <Alert tone="danger">{error}</Alert>}
      {check && (
        <>
          {compare ? <LiveComparison compare={compare} /> : <p className="mb-1 text-xs text-muted-foreground">{t('access.check.inspectHint')}</p>}
          <VerdictList check={check} compare={compare} serviceId={serviceId} />
        </>
      )}
    </div>
  )
}

/** The token page: which tools of its server the token may call, and why not the others. */
export function TokenToolsCard({ token, policyStatus }) {
  const { t } = useTranslation()
  const active = token.status === 'active'
  const { check, error, loading } = useAccessCheck(token.service_id, token.service_id && active ? { jti: token.jti } : null)
  const e = enforcement(policyStatus)
  return (
    <Card data-testid="token-tools">
      <CardHeader
        title={t('access.check.tokenTitle')}
        description={token.service_id
          ? <>{t('access.check.tokenSubtitle')} <Link to={`/services/${encodeURIComponent(token.service_id)}?tab=access`} className="text-link transition-colors duration-200 hover:text-link-hover">{token.service_name}</Link></>
          : t('access.check.tokenNoService')}
      />
      {!token.service_id ? null : !active ? (
        <p className="text-sm text-muted-foreground" data-testid="token-tools-inactive">{t('access.check.tokenInactive')}</p>
      ) : (
        <>
          {loading && <Spinner />}
          {error && <Alert tone="danger">{error}</Alert>}
          {e && e.key !== 'enforced' && (
            <div className="mb-3"><Alert tone={e.tone === 'warning' ? 'warning' : 'neutral'} title={t(`access.enforcement.${e.key}.title`)}>{t('access.check.notEnforcedNote')}</Alert></div>
          )}
          {check && (
            <>
              <div className="mb-2"><VerdictCounts counts={check.counts} /></div>
              <VerdictList check={check} serviceId={token.service_id} />
            </>
          )}
        </>
      )}
    </Card>
  )
}
