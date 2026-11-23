import { useState, useEffect, useCallback } from 'react'
import { formatDate } from '../utils/format'
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  Copy, Check, Trash2, Clock, RefreshCw, ChevronDown,
  Activity, Key, Edit3, Wrench, Code2, ShieldCheck, ShieldX, ShieldAlert, CheckCheck, ScanSearch,
} from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { servicesApi, statsApi, oauthApi } from '../services/api'
import LastChecked from '../components/LastChecked'
import CodeBlock from '../components/CodeBlock'
import ServiceFormModal from '../components/ServiceFormModal'
import HealthIndicator from '../components/HealthIndicator'
import ScopeEditor from '../components/ScopeEditor'
import ClientConfigPanel from '../components/ClientConfigPanel'
import MarkdownLite from '../components/MarkdownLite'
import { copyToClipboard } from '../utils/clipboard'
import { feedTone, revocationReachesServer } from '../utils/revocation'
import { toolChanges } from '../utils/toolDiff'
import { countBySeverity, excerptSegments, groupByRule, highlightSegments, needlesFor, plainText, sortFindings, toolsNeedingConfirm } from '../utils/toolFindings'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import { KindBadge, StatusBadge, ScopeChips } from './TokensPage'
import clsx from 'clsx'
import {
  PageHeader, Button, IconButton, Badge, StatusDot, Card, CardHeader, SectionLabel, DescriptionList,
  EmptyState, Alert, LoadingBlock, SegmentedControl, Select,
} from '../components/ui'

// recharts stroke attrs cannot read CSS vars: give fallback colors; the real line color
// follows the theme via index.css .chart-line-*
const CHART = { success: '#22C55E', failed: '#F87171' }

function CustomTooltip({ active, payload, label }) {
  const { t } = useTranslation()
  if (!active || !payload || !payload.length) return null
  const success = payload.find((p) => p.dataKey === 'success')?.value || 0
  const failed = payload.find((p) => p.dataKey === 'failed')?.value || 0
  return (
    <div className="min-w-[10rem] rounded-md border border-border bg-popover p-3 text-xs shadow-overlay">
      <p className="mb-2 font-medium text-foreground">{label}</p>
      <div className="flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="success" />{t('services.detail.chartSuccess')}</span><span className="tabular-nums text-foreground">{success}</span></div>
      <div className="mt-1 flex items-center justify-between gap-4"><span className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="danger" />{t('services.detail.chartFailed')}</span><span className="tabular-nums text-foreground">{failed}</span></div>
      <div className="mt-2 flex items-center justify-between gap-4 border-t border-border pt-1.5"><span className="text-muted-foreground">{t('services.detail.totalLabel')}</span><span className="tabular-nums font-medium text-foreground">{success + failed}</span></div>
    </div>
  )
}

/** Whether revoking a token reaches this server before the token expires (its resource servers' feed polls) */
function RevocationFeedStatus({ status }) {
  const { t } = useTranslation()
  const polled = status.state === 'active' || status.state === 'stale'
  return (
    <span className="block break-normal font-sans">
      <span className="flex flex-wrap items-center justify-end gap-1.5">
        <StatusDot tone={feedTone(status.state)} />
        {polled ? (
          <>
            <span>{status.state === 'active' ? t('services.detail.feedActive') : t('services.detail.feedStale')}</span>
            <LastChecked value={status.last_poll} withIcon={false} className="text-foreground" />
          </>
        ) : (
          <span>{status.state === 'never_polled' ? t('services.detail.feedNeverPolled') : t('services.detail.feedNotWired')}</span>
        )}
      </span>
      {!revocationReachesServer(status.state) && (
        <span className="mt-1 block text-xs text-muted-foreground">{t('services.detail.feedHint')}</span>
      )}
    </span>
  )
}

/** Whether this server enforces tool approvals: its pinning middleware's polls of the tool policy feed (#33) */
function PolicyFeedStatus({ status }) {
  const { t } = useTranslation()
  const polled = status.state === 'active' || status.state === 'stale'
  return (
    <span className="block break-normal font-sans" data-testid="policy-feed-status">
      <span className="flex flex-wrap items-center justify-end gap-1.5">
        <StatusDot tone={status.state === 'not_wired' ? 'neutral' : feedTone(status.state)} />
        {polled ? (
          <>
            <span>{status.state === 'active' ? t('services.detail.policyActive') : t('services.detail.policyStale')}</span>
            <LastChecked value={status.last_poll} withIcon={false} className="text-foreground" />
          </>
        ) : (
          <span>{status.state === 'never_polled' ? t('services.detail.policyNeverPolled') : t('services.detail.policyNotWired')}</span>
        )}
      </span>
      {status.state !== 'active' && (
        <span className="mt-1 block text-xs text-muted-foreground">{t('services.detail.policyHint')}</span>
      )}
    </span>
  )
}

/** First meaningful line of a tool description, with markdown emphasis / headings stripped, for the collapsed row. */
function toolSummary(description) {
  const line = (description || '').split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0) || ''
  return line.replace(/^#+\s*/, '').replace(/\*\*(.*?)\*\*/g, '$1').replace(/`/g, '')
}

/** A JSON-schema object's properties as rows: name, type (+ enum / default), required, description. */
function schemaRows(schema) {
  const props = schema?.properties || {}
  const required = new Set(schema?.required || [])
  return Object.entries(props).map(([name, def]) => {
    const d = def && typeof def === 'object' ? def : {}
    const type = Array.isArray(d.type) ? d.type.join(' | ') : (d.type || (d.enum ? 'enum' : d.anyOf ? 'any' : 'object'))
    return { name, type, enum: Array.isArray(d.enum) ? d.enum : null, def: d.default, description: d.description || '', required: required.has(name) }
  })
}

function ToolSchema({ schema }) {
  const { t } = useTranslation()
  const [view, setView] = useState('table')
  const rows = schemaRows(schema)
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background/60">
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-subtle-foreground">{t('services.common.inputSchema')}</span>
        <SegmentedControl
          size="sm"
          value={view}
          onChange={setView}
          items={[{ key: 'table', label: t('services.common.schemaView.table') }, { key: 'json', label: 'JSON' }]}
        />
      </div>
      {view === 'json' ? (
        <pre className="max-h-64 overflow-auto p-3 font-mono text-[11px] leading-relaxed text-foreground">{JSON.stringify(schema, null, 2)}</pre>
      ) : rows.length === 0 ? (
        <p className="px-3 py-2.5 text-xs text-muted-foreground">{t('services.common.noParams')}</p>
      ) : (
        <div className="max-h-64 overflow-auto">
          <div className="divide-y divide-border">
            {rows.map((r) => (
              <div key={r.name} className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <code className="font-mono text-xs font-medium text-foreground">{r.name}</code>
                  <Badge tone="neutral" mono>{r.type}</Badge>
                  {r.required && <Badge tone="warning">{t('services.common.paramRequired')}</Badge>}
                  {r.def !== undefined && (
                    <span className="text-[11px] text-subtle-foreground">{t('services.common.paramDefault')} <code className="font-mono text-foreground">{JSON.stringify(r.def)}</code></span>
                  )}
                </div>
                {r.enum && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {r.enum.map((v) => <Badge key={String(v)} tone="neutral" mono size="sm">{String(v)}</Badge>)}
                  </div>
                )}
                {r.description && <p className="mt-1 text-xs text-muted-foreground">{r.description}</p>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/** The approval state of a tool as a badge (#32); approved tools show none unless asked. */
function ToolStateBadge({ tool, showApproved = false }) {
  const { t } = useTranslation()
  if (tool.removed_at) return <Badge tone="neutral">{t('services.toolPin.state.removed')}</Badge>
  if (tool.state === 'pending') return <Badge tone="warning">{t('services.toolPin.state.pending')}</Badge>
  if (tool.state === 'rejected') return <Badge tone="danger">{t('services.toolPin.state.rejected')}</Badge>
  return showApproved ? <Badge tone="success">{t('services.toolPin.state.approved')}</Badge> : null
}

function ToolItem({ tool, onDecide, deciding }) {
  const { t } = useTranslation()
  const [isExpanded, setIsExpanded] = useState(false)
  const toast = useToast()
  const summary = toolSummary(tool.description)
  const paramCount = Object.keys(tool.input_schema?.properties || {}).length
  const handleCopySchema = async () => {
    try {
      await copyToClipboard(JSON.stringify(tool.input_schema, null, 2))
      toast.success(t('services.common.schemaCopied'))
    } catch {
      toast.error(t('services.common.schemaCopyFailed'))
    }
  }
  const busy = deciding === tool.hash
  return (
    <div className={clsx('group -mx-2 rounded-lg transition-colors duration-150', isExpanded ? 'bg-muted/40' : 'hover:bg-muted/40', tool.removed_at && 'opacity-70')}>
      <div className="flex items-center gap-3 px-2 py-2">
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex min-w-0 flex-1 items-center gap-3 text-left"
          aria-expanded={isExpanded}
        >
          <span className={clsx(
            'flex h-7 w-7 shrink-0 items-center justify-center rounded-md border transition-colors duration-150',
            isExpanded ? 'border-primary/40 bg-primary-soft/60 text-primary-soft-foreground' : 'border-border bg-muted text-subtle-foreground',
          )}>
            <Wrench className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex min-w-0 items-center gap-2">
              <span className="truncate font-mono text-xs font-medium text-foreground">{tool.name}</span>
              <ToolStateBadge tool={tool} />
              {tool.flagged && <FlaggedBadge findings={tool.findings} />}
            </span>
            {/* Collapsed: one line only. Long agent-facing descriptions (headings, mode tables, rules) open on click. */}
            {summary && <span className="mt-0.5 block truncate text-xs text-muted-foreground" title={summary}>{summary}</span>}
          </span>
          {paramCount > 0 && (
            <span className="hidden shrink-0 text-[11px] tabular-nums text-subtle-foreground sm:inline">{t('services.common.paramCount', { n: paramCount })}</span>
          )}
          <ChevronDown className={clsx('h-4 w-4 shrink-0 text-subtle-foreground transition-transform duration-200', isExpanded && 'rotate-180')} aria-hidden="true" />
        </button>
      </div>
      {isExpanded && (
        <div className="space-y-3 px-2 pb-3 pl-12">
          {tool.description && (
            <div className="max-h-72 overflow-auto rounded-lg border border-border border-l-2 border-l-primary/60 bg-background/60 px-3.5 py-3">
              <MarkdownLite text={tool.description} />
            </div>
          )}
          {tool.input_schema && <ToolSchema schema={tool.input_schema} />}
          {tool.findings?.length > 0 && <ToolFindings findings={tool.findings} />}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="min-w-0 truncate font-mono text-[11px] text-subtle-foreground" title={tool.hash || ''}>
              {t('services.toolPin.hashLabel')} {tool.hash ? tool.hash.slice(0, 12) : '—'} · {t('services.toolPin.versionCount', { count: tool.versions?.length || 0 })}
            </span>
            <span className="flex flex-wrap items-center gap-1">
              {tool.hash && tool.state === 'rejected' && (
                <Button variant="ghost" size="xs" icon={ShieldCheck} loading={busy} onClick={() => onDecide(tool, 'approve')}>{t('services.toolPin.approve')}</Button>
              )}
              {tool.hash && tool.state === 'approved' && (
                <Button variant="ghost" size="xs" icon={ShieldX} loading={busy} onClick={() => onDecide(tool, 'reject')}>{t('services.toolPin.withdraw')}</Button>
              )}
              {tool.input_schema && (
                <Button variant="ghost" size="xs" icon={Copy} onClick={handleCopySchema}>{t('services.common.copyInputSchema')}</Button>
              )}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

const DIFF_LINE = {
  add: 'bg-success/10 text-foreground',
  del: 'bg-danger/10 text-muted-foreground line-through decoration-danger/40',
  same: 'text-muted-foreground',
}
const DIFF_MARK = { add: '+', del: '−', same: ' ' }

/** One changed field: its line diff, wrapped (never a horizontal scroll on a phone). */
function FieldDiff({ field, lines, folded = false, needles = [] }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(!folded)
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background/60">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className={clsx('flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-[11px] font-semibold uppercase tracking-wide text-subtle-foreground', open && 'border-b border-border')}
      >
        {t(`services.toolPin.field.${field}`)}
        <ChevronDown className={clsx('h-3.5 w-3.5 shrink-0 transition-transform duration-200', open && 'rotate-180')} aria-hidden="true" />
      </button>
      {open && <div className="max-h-72 overflow-y-auto py-1 font-mono text-[11px] leading-relaxed">
        {lines.map((l, i) => (
          <div key={i} className={clsx('flex gap-2 px-3', DIFF_LINE[l.op])}>
            <span className={clsx('w-3 shrink-0 select-none', l.op === 'add' ? 'text-success' : l.op === 'del' ? 'text-danger' : 'text-subtle-foreground')} aria-hidden="true">{DIFF_MARK[l.op]}</span>
            <span className="min-w-0 flex-1 whitespace-pre-wrap break-words [overflow-wrap:anywhere]">{l.text ? <Highlighted text={l.text} needles={l.op === 'del' ? [] : needles} /> : ' '}</span>
          </div>
        ))}
      </div>}
    </div>
  )
}

// On a new tool every field is an addition: the text fields are open, the schemas folded so the card stays short
const FOLDED_WHEN_NEW = new Set(['inputSchema', 'outputSchema', 'annotations'])

/** A pending tool version to approve or reject, compared with the approved one (or shown whole when it is new). */
function ToolApprovalCard({ tool, onDecide, deciding }) {
  const { t } = useTranslation()
  const current = (tool.versions || []).find((v) => v.hash === tool.hash)
  const before = tool.approved_version?.definition || null
  const changes = toolChanges(before, current?.definition || {})
  const findings = current?.findings || tool.findings || []
  const busy = deciding === tool.hash
  return (
    <div className="rounded-lg border border-warning/30 bg-warning/5 p-3" data-testid="tool-approval-card">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
            <span className="break-all font-mono text-xs font-semibold text-foreground">{tool.name}</span>
            <Badge tone={before ? 'warning' : 'info'}>{before ? t('services.toolPin.changed') : t('services.toolPin.newTool')}</Badge>
            {current?.source && (
              <Badge tone="neutral" title={current.source === 'reported' ? t('services.toolPin.sourceReportedHint') : undefined}>
                {t(`services.toolPin.source.${current.source === 'reported' ? 'reported' : 'scan'}`)}
              </Badge>
            )}
            {findings.length > 0 && <FlaggedBadge findings={findings} showInfo />}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {before ? t('services.toolPin.changedHint', { date: formatDate(tool.approved_version.decided_at) }) : t('services.toolPin.newHint')}
          </p>
        </div>
        <div className="flex shrink-0 gap-1.5">
          <Button variant="secondary" size="xs" icon={ShieldX} loading={busy} onClick={() => onDecide(tool, 'reject')}>{t('services.toolPin.reject')}</Button>
          <Button variant="primary" size="xs" icon={ShieldCheck} loading={busy} onClick={() => onDecide(tool, 'approve')}>{t('services.toolPin.approve')}</Button>
        </div>
      </div>
      {findings.length > 0 && <ToolFindings findings={findings} className="mt-3" />}
      <div className="mt-3 space-y-2">
        {changes.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t('services.toolPin.noFieldChanges')}</p>
        ) : changes.map((c) => {
          const needles = needlesFor(findings, c.field)
          // a schema with a finding opens even on a new tool, so the highlighted text is in view
          return <FieldDiff key={c.field} field={c.field} lines={c.lines} needles={needles} folded={!before && FOLDED_WHEN_NEW.has(c.field) && needles.length === 0} />
        })}
      </div>
      <p className="mt-2 break-all font-mono text-[11px] text-subtle-foreground">
        {before && <>{tool.approved_version.hash.slice(0, 12)} → </>}{tool.hash}
      </p>
    </div>
  )
}

const SEVERITY_TONE = { high: 'danger', warning: 'warning', info: 'neutral' }

/** An invisible character made visible: a small boxed code point label. */
function InvisibleChar({ label, mark = false }) {
  return (
    <span className={clsx('mx-px inline-block rounded-sm border px-0.5 align-baseline font-mono text-[10px] leading-none',
      mark ? 'border-danger/50 bg-danger/15 text-danger' : 'border-warning/50 bg-warning/15 text-warning')}
    title={label} data-testid="invisible-char">{label}</span>
  )
}

/** Text with the scan's matches highlighted and every invisible character shown as its code point. */
function Highlighted({ text, needles = [] }) {
  return highlightSegments(text, needles).map((seg, i) => {
    if (seg.invisible) return <InvisibleChar key={i} label={seg.invisible} mark={seg.mark} />
    return seg.mark
      ? <mark key={i} className="rounded-sm bg-danger/20 px-px text-foreground ring-1 ring-inset ring-danger/40" data-testid="finding-mark">{seg.text}</mark>
      : <span key={i}>{seg.text}</span>
  })
}

/** "Flagged" chip on a tool: the most severe finding's tone and the counts in its tooltip. */
function FlaggedBadge({ findings, showInfo = false }) {
  const { t } = useTranslation()
  const counts = countBySeverity(findings)
  const severity = counts.high ? 'high' : counts.warning ? 'warning' : 'info'
  if (severity === 'info' && !showInfo) return null
  const total = counts.high + counts.warning + counts.info
  return (
    <Badge tone={SEVERITY_TONE[severity]} title={t('services.toolScan.countsHint', counts)} data-testid="tool-flagged-badge">
      <ScanSearch className="h-3 w-3" aria-hidden="true" />
      {severity === 'info' ? t('services.toolScan.notes', { count: total }) : t('services.toolScan.flagged', { count: counts.high + counts.warning })}
    </Badge>
  )
}

/** What the poisoning scan found in one definition, grouped by rule, with the matched text (#34). */
function ToolFindings({ findings, className }) {
  const { t } = useTranslation()
  const groups = groupByRule(findings)
  const [showInfo, setShowInfo] = useState(false)
  const visible = groups.filter((g) => showInfo || g.severity !== 'info')
  const hiddenInfo = groups.filter((g) => g.severity === 'info').reduce((n, g) => n + g.findings.length, 0)
  return (
    <div className={clsx('rounded-lg border border-border bg-background/60 p-3', className)} data-testid="tool-findings">
      <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-foreground">
        <ScanSearch className="h-3.5 w-3.5 shrink-0 text-subtle-foreground" aria-hidden="true" />
        {t('services.toolScan.title')}
        <span className="font-normal text-muted-foreground">{t('services.toolScan.notBlocking')}</span>
      </div>
      <ul className="mt-2 space-y-2.5">
        {visible.map((g) => (
          <li key={g.rule} className="min-w-0" data-testid={`finding-${g.rule}`}>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={SEVERITY_TONE[g.severity]}>{t(`services.toolScan.severity.${g.severity}`)}</Badge>
              <span className="text-xs font-medium text-foreground">{t(`services.toolScan.rule.${g.rule}.label`)}</span>
              {g.findings.length > 1 && <span className="text-[11px] tabular-nums text-subtle-foreground">×{g.findings.length}</span>}
            </div>
            <p className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{t(`services.toolScan.rule.${g.rule}.explain`)}</p>
            <ul className="mt-1 space-y-1">
              {sortFindings(g.findings).slice(0, 6).map((f, i) => (
                <li key={i} className="min-w-0 rounded-md bg-muted/50 px-2 py-1 font-mono text-[11px] leading-relaxed">
                  {f.path && <span className="mr-1.5 break-all text-subtle-foreground">{f.path}</span>}
                  {g.findings.length > 1 && f.severity !== g.severity && <Badge tone={SEVERITY_TONE[f.severity]} className="mr-1">{t(`services.toolScan.severity.${f.severity}`)}</Badge>}
                  <span className="whitespace-pre-wrap break-words text-foreground [overflow-wrap:anywhere]">
                    {excerptSegments(f.excerpt).map((seg, j) => (seg.invisible
                      ? <InvisibleChar key={j} label={seg.invisible} mark />
                      : <span key={j}>{seg.text}</span>))}
                  </span>
                  {f.detail && <span className="mt-0.5 block whitespace-pre-wrap break-words text-warning [overflow-wrap:anywhere]">{f.detail}</span>}
                </li>
              ))}
              {g.findings.length > 6 && <li className="text-[11px] text-subtle-foreground">{t('services.toolScan.more', { count: g.findings.length - 6 })}</li>}
            </ul>
          </li>
        ))}
      </ul>
      {hiddenInfo > 0 && (
        <button type="button" className="mt-2 text-[11px] text-link transition-colors duration-200 hover:text-link-hover" onClick={() => setShowInfo(!showInfo)}>
          {showInfo ? t('services.toolScan.hideInfo') : t('services.toolScan.showInfo', { count: hiddenInfo })}
        </button>
      )}
    </div>
  )
}

/** The confirm text for approving definitions with high-severity findings: one line per finding, a few at most. */
function highFindingLines(t, tools) {
  const lines = []
  for (const tool of tools) {
    for (const f of sortFindings(tool.findings).filter((x) => x.severity === 'high')) {
      // the matched text without its invisible characters (they are listed by the rule name), kept short
      const text = plainText(f.match)
      lines.push(`• ${tool.name}: ${t(`services.toolScan.rule.${f.rule}.label`)}${text ? ` — “${text.length > 60 ? `${text.slice(0, 60)}…` : text}”` : ''}`)
    }
  }
  return lines.length > 6 ? [...lines.slice(0, 6), t('services.toolScan.more', { count: lines.length - 6 })] : lines
}

/** Turn a raw health-check exception into a short, translated label; the raw text stays in the tooltip. */
function describeHealthError(t, raw) {
  const text = String(raw || '')
  if (/timed? ?out/i.test(text)) return t('services.health.timeout')
  if (/cannot connect|connection (refused|failed|reset)|connect call failed|unreachable|name resolution/i.test(text)) return t('services.health.unreachable')
  return t('services.health.failed')
}

// Server-side integration snippets (FastMCP); the backend key is `fastmcp_${variant}`. MCP client configuration
// (Claude Code, Cursor, VS Code, Codex) lives in the "Connect a client" panel (#36).
const FASTMCP_VARIANTS = ['server', 'hooks', 'client']

export default function ServiceDetailPage() {
  const { t } = useTranslation()
  const { serviceId } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const { confirm, confirmDelete, confirmTokenRevoke } = useConfirm()
  const toast = useToast()
  const decodedServiceId = decodeURIComponent(serviceId)

  const [service, setService] = useState(null)
  const [scopes, setScopes] = useState([])
  const [ownScopes, setOwnScopes] = useState([])
  // Who the tools/list request looks like to the server: 'scanner' | 'token:<jti>' (remembered per service)
  const [refreshIdentity, setRefreshIdentity] = useState(() => {
    try { return localStorage.getItem(`refreshIdentity:${decodedServiceId}`) || 'scanner' } catch { return 'scanner' }
  })
  const [isLoadingOwnScopes, setIsLoadingOwnScopes] = useState(true)
  const [snippets, setSnippets] = useState(null)
  const [snippetVariant, setSnippetVariant] = useState('server')
  const [tokens, setTokens] = useState([])
  const [usageStats, setUsageStats] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [isLoadingStats, setIsLoadingStats] = useState(true)
  const [error, setError] = useState(null)
  const [copiedEndpoint, setCopiedEndpoint] = useState(false)
  const [isCheckingHealth, setIsCheckingHealth] = useState(false)
  const [isRefreshingTools, setIsRefreshingTools] = useState(false)
  const [decidingHash, setDecidingHash] = useState(null)
  const [isApprovingAll, setIsApprovingAll] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [revokingJti, setRevokingJti] = useState(null)
  const [feedStatus, setFeedStatus] = useState(null)
  const [policyStatus, setPolicyStatus] = useState(null)

  const reloadOwnScopes = useCallback(async () => {
    const res = await oauthApi.serviceScopes.list(decodedServiceId)
    setOwnScopes(res.own || [])
  }, [decodedServiceId])

  const saveOwnScope = async ({ name, description, isDefault }) => {
    try {
      await oauthApi.serviceScopes.upsert(decodedServiceId, name, { description, isDefault })
      toast.success(t('clients.scopes.saved'))
      await reloadOwnScopes()
      return true
    } catch (err) {
      toast.error(err.message || t('clients.scopes.saveFailed'))
      return false
    }
  }

  const deleteOwnScope = async (name) => {
    const ok = await confirmDelete(t('clients.scopes.deleteTarget', { name }))
    if (!ok) return
    try {
      await oauthApi.serviceScopes.delete(decodedServiceId, name)
      toast.success(t('clients.scopes.deleted'))
      await reloadOwnScopes()
    } catch (err) {
      toast.error(err.message || t('clients.scopes.deleteFailed'))
    }
  }

  const reload = useCallback(async () => {
    const updated = await servicesApi.getById(decodedServiceId, true)
    setService(updated)
    return updated
  }, [decodedServiceId])

  useEffect(() => {
    let cancelled = false
    setIsLoading(true)
    setError(null)
    Promise.all([
      servicesApi.getById(decodedServiceId, true),
      oauthApi.scopes.list().catch(() => ({ scopes: [] })),
      oauthApi.snippets(decodedServiceId).catch(() => null),
      oauthApi.tokens.list({ serviceId: decodedServiceId }).catch(() => ({ tokens: [] })),
      oauthApi.serviceScopes.list(decodedServiceId).catch(() => ({ own: [] })),
      oauthApi.revocationFeed.forService(decodedServiceId).catch(() => null),
      oauthApi.policyFeed.forService(decodedServiceId).catch(() => null),
    ]).then(([svc, sc, sn, tk, own, feed, policy]) => {
      if (cancelled) return
      setService(svc)
      setFeedStatus(feed)
      setPolicyStatus(policy)
      setScopes(sc.scopes || [])
      setSnippets(sn)
      setTokens(tk.tokens || [])
      setOwnScopes(own.own || [])
      setIsLoadingOwnScopes(false)
    }).catch((err) => {
      if (!cancelled) setError(err.message || t('services.detail.loadFailed'))
    }).finally(() => { if (!cancelled) setIsLoading(false) })
    return () => { cancelled = true }
  }, [decodedServiceId, t])

  useEffect(() => {
    if (!service) return
    let cancelled = false
    setIsLoadingStats(true)
    statsApi.daily(30, service.id)
      .then((res) => { if (!cancelled) setUsageStats(res.stats || []) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setIsLoadingStats(false) })
    return () => { cancelled = true }
  }, [service?.id])   // eslint-disable-line react-hooks/exhaustive-deps

  // "Connect" on the services list links to #connect: scroll there once the page has rendered
  const hasService = !!service
  useEffect(() => {
    if (!hasService || location.hash !== '#connect') return
    const el = document.getElementById('connect')
    if (el) el.scrollIntoView({ block: 'start' })
  }, [hasService, location.hash])

  const handleCopy = async (text) => {
    try {
      await copyToClipboard(text)
      setCopiedEndpoint(true)
      toast.success(t('services.common.endpointCopied'))
      setTimeout(() => setCopiedEndpoint(false), 2000)
    } catch {
      toast.error(t('services.common.endpointCopyFailed'))
    }
  }

  const handleCheckHealth = async () => {
    setIsCheckingHealth(true)
    try {
      const result = await servicesApi.checkHealth(decodedServiceId)
      toast.success(t('services.detail.healthCheckResult', { status: result.status }))
      await reload()
    } catch (err) {
      toast.error(t('services.detail.healthCheckFailed', { message: err.message }))
    } finally {
      setIsCheckingHealth(false)
    }
  }

  const chooseRefreshIdentity = (value) => {
    setRefreshIdentity(value)
    try { localStorage.setItem(`refreshIdentity:${decodedServiceId}`, value) } catch { /* per-viewer convenience only */ }
  }

  // Active PATs / OAuth access tokens of this server that the tools list can be fetched as
  const inspectableTokens = tokens.filter((tk) => tk.status === 'active' && (tk.kind === 'pat' || tk.kind === 'access'))
  const selectedInspectToken = refreshIdentity.startsWith('token:')
    ? inspectableTokens.find((tk) => tk.jti === refreshIdentity.slice(6)) || null
    : null
  const refreshMode = refreshIdentity.startsWith('token:') ? 'token' : 'scanner'

  const handleRefreshTools = async () => {
    if (refreshMode === 'token' && !selectedInspectToken) {
      toast.error(t('services.detail.refreshTokenGone'))
      chooseRefreshIdentity('scanner')
      return
    }
    setIsRefreshingTools(true)
    try {
      const result = await servicesApi.refreshTools(decodedServiceId, {
        identity: refreshMode,
        jti: refreshMode === 'token' ? selectedInspectToken.jti : null,
      })
      toast.success(result.tools_pending > 0
        ? t('services.toolPin.refreshedWithPending', { n: result.tools_count, count: result.tools_pending })
        : t('services.detail.refreshToolsSuccess', { n: result.tools_count }))
      await reload()
    } catch (err) {
      toast.error(t('services.detail.refreshToolsFailed', { message: err.message }))
    } finally {
      setIsRefreshingTools(false)
    }
  }

  // Approving a definition the scan rated high asks once, naming what it found (#34); anything else is one click
  const confirmHighFindings = async (tools) => {
    const flagged = toolsNeedingConfirm(tools)
    if (flagged.length === 0) return true
    return confirm({
      title: t('services.toolScan.confirmTitle', { count: flagged.length }),
      message: `${t('services.toolScan.confirmMessage')}\n\n${highFindingLines(t, flagged).join('\n')}`,
      confirmText: t('services.toolScan.confirmApprove'),
      type: 'warning',
    })
  }

  const handleDecideTool = async (tool, decision) => {
    if (decision === 'approve' && !(await confirmHighFindings([tool]))) return
    setDecidingHash(tool.hash)
    try {
      if (decision === 'approve') await servicesApi.approveTool(decodedServiceId, tool.id, tool.hash)
      else await servicesApi.rejectTool(decodedServiceId, tool.id, tool.hash)
      toast.success(t(decision === 'approve' ? 'services.toolPin.approvedToast' : 'services.toolPin.rejectedToast', { name: tool.name }))
      await reload()
    } catch (err) {
      toast.error(t('services.toolPin.decideFailed', { message: err.message }))
      await reload().catch(() => {})
    } finally {
      setDecidingHash(null)
    }
  }

  const handleApproveAll = async (pendingTools) => {
    if (!(await confirmHighFindings(pendingTools))) return
    setIsApprovingAll(true)
    try {
      const res = await servicesApi.approveAllTools(decodedServiceId, pendingTools.map((tl) => tl.hash))
      toast.success(t('services.toolPin.approvedAllToast', { count: res.approved }))
      await reload()
    } catch (err) {
      toast.error(t('services.toolPin.decideFailed', { message: err.message }))
      await reload().catch(() => {})
    } finally {
      setIsApprovingAll(false)
    }
  }

  const handleUpdate = async (fields) => {
    await servicesApi.update(decodedServiceId, fields)
    await reload()
    oauthApi.snippets(decodedServiceId).then(setSnippets).catch(() => {})
    toast.success(t('services.detail.updateSuccess'))
  }

  const handleDelete = async () => {
    if (!service) return
    const confirmed = await confirmDelete(t('services.detail.deleteConfirmTarget', { name: service.name }))
    if (!confirmed) return
    try {
      await servicesApi.delete(decodedServiceId)
      toast.success(t('services.detail.deleteSuccess', { name: service.name }))
      navigate('/services')
    } catch (err) {
      toast.error(t('services.detail.deleteFailed', { message: err.message }))
    }
  }

  const handleRevokeToken = async (tk) => {
    const ok = await confirmTokenRevoke(tk)
    if (!ok) return
    setRevokingJti(tk.jti)
    try {
      await oauthApi.tokens.revoke(tk.jti)
      toast.success(t('tokens.list.revokeSuccess'))
      const res = await oauthApi.tokens.list({ serviceId: decodedServiceId })
      setTokens(res.tokens || [])
    } catch (err) {
      toast.error(t('tokens.list.revokeFail', { message: err.message }))
    } finally {
      setRevokingJti(null)
    }
  }

  if (isLoading) {
    return <LoadingBlock className="min-h-[400px]" />
  }

  if (error || !service) {
    return (
      <div className="space-y-8">
        <PageHeader
          title={t('services.detail.subtitleType')}
          backTo="/services"
          backLabel={t('services.detail.backToServices')}
        />
        <Alert tone="danger">{error || t('services.detail.loadFailed')}</Alert>
      </div>
    )
  }

  const allTools = service.tools || []
  const listedTools = allTools.filter((tl) => !tl.removed_at)
  const removedTools = allTools.filter((tl) => tl.removed_at)
  const pendingTools = listedTools.filter((tl) => tl.state === 'pending')
  // Approve all is for a service's first tool list only: nothing of it was ever approved
  const firstReview = !allTools.some((tl) => (tl.versions || []).some((v) => v.state === 'approved'))
  const totalSuccess = usageStats.reduce((s, x) => s + (x.success || 0), 0)
  const totalFailed = usageStats.reduce((s, x) => s + (x.failed || 0), 0)
  const totalUsage = totalSuccess + totalFailed
  const hasMcpConnection = !!(service.host && service.port)
  const activeSnippetKey = `fastmcp_${snippetVariant}`
  const activeSnippetTitle = `${t('services.detail.snippetFamily.fastmcp')} · ${t(`services.detail.snippetVariant.${snippetVariant}`)}`

  return (
    <div className="space-y-8">
      <PageHeader
        title={service.name}
        description={service.description || t('services.common.noDescription')}
        backTo="/services"
        backLabel={t('services.detail.backToServices')}
        meta={
          <>
            {service.health && <HealthIndicator status={service.health.status} />}
            {service.source === 'auto_discovered' && <Badge tone="warning">{t('services.detail.autoTag')}</Badge>}
            {service.source === 'managed' && <Badge tone="accent">{t('services.list.managedTag')}</Badge>}
            {pendingTools.length > 0 && <Badge tone="warning">{t('services.toolPin.pendingBadge', { count: pendingTools.length })}</Badge>}
          </>
        }
        actions={
          <>
            {hasMcpConnection && (
              <IconButton
                variant="secondary"
                icon={isCheckingHealth ? RefreshCw : Activity}
                title={t('services.detail.healthCheck')}
                onClick={handleCheckHealth}
                disabled={isCheckingHealth}
                className={clsx(isCheckingHealth && 'animate-spin')}
              />
            )}
            <Button variant="secondary" icon={Edit3} onClick={() => setShowEditModal(true)}>
              {t('services.detail.edit')}
            </Button>
            <Button variant="primary" icon={Key} to={`/tokens/create?service_id=${encodeURIComponent(service.id)}`}>
              {t('services.detail.issuePat')}
            </Button>
            <Button variant="destructive" icon={Trash2} onClick={handleDelete}>
              {t('services.detail.delete')}
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Left column */}
        <div className="space-y-4 lg:col-span-2">
          {/* Connection */}
          <Card>
            <CardHeader
              title={t('services.common.mcpConnection')}
              action={service.mcp_url && (
                <Button variant="ghost" size="xs" icon={copiedEndpoint ? Check : Copy} onClick={() => handleCopy(service.mcp_url)}>
                  {copiedEndpoint ? t('services.detail.copied') : t('services.detail.copy')}
                </Button>
              )}
            />
            <DescriptionList
              items={[
                { label: t('services.detail.mcpUrl'), value: service.mcp_url || t('services.tools.noConnection'), mono: !!service.mcp_url },
                { label: t('services.detail.hostLabel'), value: service.host || '—', mono: !!service.host },
                { label: t('services.detail.portLabel'), value: service.port || '—', mono: !!service.port },
                { label: t('services.detail.protocolLabel'), value: (service.protocol || 'http').toUpperCase(), mono: true },
                { label: t('services.detail.mcpPathLabel'), value: service.mcp_path || '/mcp', mono: true },
                {
                  label: t('services.detail.audienceLabel'),
                  value: (
                    <span>
                      <span className="block break-all font-mono text-xs">{service.effective_audience || '—'}</span>
                      <span className="mt-1 block text-xs font-sans text-muted-foreground">
                        {service.oauth_audience ? t('services.detail.audienceCustom') : t('services.detail.audienceDefault')}
                      </span>
                    </span>
                  ),
                },
                {
                  label: t('services.detail.authRequired'),
                  value: service.requires_auth ? t('services.detail.yes') : t('services.detail.no'),
                },
                ...(feedStatus && service.effective_audience ? [{
                  label: t('services.detail.revocationFeed'),
                  value: <RevocationFeedStatus status={feedStatus} />,
                }] : []),
                ...(policyStatus && service.effective_audience ? [{
                  label: t('services.detail.toolPolicy'),
                  value: <PolicyFeedStatus status={policyStatus} />,
                }] : []),
              ]}
            />
            {(service.has_static_token || service.health?.response_time_ms != null || service.health?.last_checked || service.created_at || service.health?.error_message) && (
            <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-4 text-xs text-muted-foreground">
              {service.has_static_token && (
                <Badge tone="neutral"><Key className="h-3 w-3" />{t('services.detail.staticTokenBadge')}</Badge>
              )}
              {service.health?.response_time_ms != null && (
                <span className="flex items-center gap-1.5">
                  <Activity className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('services.detail.responseTime')}
                  <span className="font-mono tabular-nums text-foreground">{Math.round(service.health.response_time_ms)}ms</span>
                </span>
              )}
              {service.health?.last_checked && (
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('services.detail.lastChecked')}
                  <LastChecked value={service.health.last_checked} withIcon={false} className="text-foreground" />
                </span>
              )}
              {service.created_at && (
                <span className="tabular-nums">{t('services.detail.createdAt', { date: formatDate(service.created_at) })}</span>
              )}
              {service.health?.error_message && (
                <span className="max-w-full truncate text-danger" title={service.health.error_message}>{describeHealthError(t, service.health.error_message)}</span>
              )}
            </div>
            )}
          </Card>

          {/* Usage */}
          <Card>
            <CardHeader
              title={t('services.detail.usageHistoryTitle')}
              description={t('services.detail.usageHistorySubtitle')}
              action={
                <dl className="flex items-center divide-x divide-border text-xs">
                  <div className="pr-4"><dt className="text-muted-foreground">{t('services.detail.totalLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalUsage}</dd></div>
                  <div className="px-4"><dt className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="success" />{t('services.detail.successLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalSuccess}</dd></div>
                  <div className="pl-4"><dt className="flex items-center gap-1.5 text-muted-foreground"><StatusDot tone="danger" />{t('services.detail.failedLabel')}</dt><dd className="text-base font-semibold tabular-nums text-foreground">{totalFailed}</dd></div>
                </dl>
              }
            />
            {isLoadingStats ? (
              <LoadingBlock className="h-64 py-0" />
            ) : totalUsage === 0 ? (
              <EmptyState className="h-64 py-0" icon={Clock} title={t('services.detail.noUsageTitle')} description={t('services.detail.noUsageHint')} />
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={usageStats} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                    <CartesianGrid vertical={false} strokeDasharray="0" />
                    <XAxis dataKey="date" fontSize={11} tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => { const d = new Date(v); return `${d.getMonth() + 1}/${d.getDate()}` }} />
                    <YAxis fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} tickMargin={4} />
                    <Tooltip content={<CustomTooltip />} cursor={{ strokeWidth: 1 }} />
                    <Area className="chart-line-success" type="monotone" dataKey="success" stroke={CHART.success} strokeWidth={2} fill={CHART.success} fillOpacity={0.08} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-success' }} name={t('services.detail.chartSuccess')} />
                    <Area className="chart-line-failed" type="monotone" dataKey="failed" stroke={CHART.failed} strokeWidth={2} fill={CHART.failed} fillOpacity={0.08} dot={false} activeDot={{ r: 4, strokeWidth: 0, className: 'fill-danger' }} name={t('services.detail.chartFailed')} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>

          {/* Connect a client (#36) */}
          <Card id="connect" className="scroll-mt-20">
            <CardHeader
              title={t('clientConfig.title')}
              description={t('clientConfig.subtitle')}
            />
            <ClientConfigPanel serviceId={decodedServiceId} />
          </Card>

          {/* Integration */}
          <Card>
            <CardHeader
              title={t('services.detail.integrationTitle')}
              description={t('services.detail.integrationSubtitle')}
            />
            {!snippets ? (
              <p className="text-sm text-muted-foreground">{t('services.detail.snippetsUnavailable')}</p>
            ) : (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <SegmentedControl
                    size="sm"
                    value={snippetVariant}
                    onChange={setSnippetVariant}
                    items={FASTMCP_VARIANTS.map((v) => ({ key: v, label: t(`services.detail.snippetVariant.${v}`), icon: Code2 }))}
                  />
                </div>
                <CodeBlock title={activeSnippetTitle} language="python" value={snippets[activeSnippetKey]} rows={22} />
                <DescriptionList
                  items={[
                    { label: t('services.detail.issuerLabel'), value: snippets.issuer, mono: true },
                    { label: t('services.detail.audienceLabel'), value: snippets.audience, mono: true },
                  ]}
                />
              </div>
            )}
          </Card>
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Scopes + tags */}
          <Card>
            <SectionLabel className="mb-2">{t('services.detail.scopesTitle')}</SectionLabel>
            {service.oauth_scopes && service.oauth_scopes.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {service.oauth_scopes.map((s) => (
                  <Badge key={s} tone="accent" mono title={scopes.find((x) => x.name === s)?.description || ''}>{s}</Badge>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">{t('services.detail.scopesAll')}</p>
            )}
            <SectionLabel className="mb-2 mt-5">{t('services.detail.tagsTitle')}</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {(service.tags || []).map((tag) => <Badge key={tag} tone="neutral">{tag}</Badge>)}
              {(!service.tags || service.tags.length === 0) && <span className="text-xs text-muted-foreground">{t('services.detail.noTags')}</span>}
            </div>
          </Card>

          {/* Scopes this server declares for itself (in addition to the global registry) */}
          <ScopeEditor
            title={t('services.detail.ownScopesTitle')}
            description={t('services.detail.ownScopesSubtitle')}
            scopes={ownScopes}
            isLoading={isLoadingOwnScopes}
            onSave={saveOwnScope}
            onDelete={deleteOwnScope}
            emptyText={t('services.detail.ownScopesEmpty')}
          />

          {/* Tools */}
          <Card>
            <CardHeader
              title={(
                <span className="flex flex-wrap items-center gap-2">
                  {t('services.detail.mcpToolsLabel')}<Badge tone="neutral">{listedTools.length}</Badge>
                  {pendingTools.length > 0 && <Badge tone="warning">{t('services.toolPin.pendingBadge', { count: pendingTools.length })}</Badge>}
                </span>
              )}
              action={hasMcpConnection && (
                <Button variant="ghost" size="xs" icon={RefreshCw} onClick={handleRefreshTools} loading={isRefreshingTools}>
                  {t('services.detail.refreshFromServer')}
                </Button>
              )}
            />
            {hasMcpConnection && (
              <div className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1.5 rounded-lg border border-border bg-muted/40 px-2.5 py-1.5">
                <Key className="h-3.5 w-3.5 shrink-0 text-subtle-foreground" aria-hidden="true" />
                <span className="shrink-0 text-[11px] font-semibold uppercase tracking-wide text-subtle-foreground">{t('services.detail.refreshAs')}</span>
                <Select
                  size="sm"
                  value={refreshIdentity}
                  onChange={(e) => chooseRefreshIdentity(e.target.value)}
                  title={t(`services.detail.refreshAsHint.${refreshMode}`)}
                  className="min-w-0 flex-1"
                >
                  <option value="scanner">{t('services.detail.refreshAsScanner')}</option>
                  {inspectableTokens.length > 0 && (
                    <optgroup label={t('services.detail.refreshAsTokenGroup')}>
                      {inspectableTokens.map((tk) => (
                        <option key={tk.jti} value={`token:${tk.jti}`}>
                          {t('services.detail.refreshAsTokenOption', {
                            kind: t(`tokens.kind.${tk.kind}`, tk.kind),
                            name: tk.label || tk.client_name || tk.user_email || tk.jti.slice(0, 8),
                          })}
                        </option>
                      ))}
                    </optgroup>
                  )}
                </Select>
                {refreshMode === 'token' && selectedInspectToken && (
                  <div className="flex w-full items-center gap-1.5 overflow-hidden pl-6">
                    <ScopeChips scopes={selectedInspectToken.scopes} max={3} />
                  </div>
                )}
              </div>
            )}
            {pendingTools.length > 0 && (
              <div className="mb-4 space-y-3" data-testid="tool-approvals">
                <Alert tone="warning" icon={ShieldAlert} title={t('services.toolPin.reviewTitle', { count: pendingTools.length })}>
                  <p>{firstReview ? t('services.toolPin.reviewFirstHint') : t('services.toolPin.reviewHint')}</p>
                  {pendingTools.some((tl) => tl.flagged) && (
                    <p className="mt-1 font-medium text-danger">{t('services.toolScan.pendingFlagged', { count: pendingTools.filter((tl) => tl.flagged).length })}</p>
                  )}
                  {policyStatus && (
                    <p className="mt-1">{policyStatus.state === 'active' ? t('services.toolPin.enforcedHint') : t('services.toolPin.notEnforcedHint')}</p>
                  )}
                  {firstReview && pendingTools.length > 1 && (
                    <Button className="mt-2" variant="primary" size="sm" icon={CheckCheck} loading={isApprovingAll} onClick={() => handleApproveAll(pendingTools)}>
                      {t('services.toolPin.approveAll', { count: pendingTools.length })}
                    </Button>
                  )}
                </Alert>
                {pendingTools.map((tool) => (
                  <ToolApprovalCard key={tool.id} tool={tool} onDecide={handleDecideTool} deciding={decidingHash} />
                ))}
              </div>
            )}
            {allTools.length === 0 ? (
              <EmptyState
                compact
                icon={Wrench}
                title={t('services.detail.noToolsFound')}
                description={hasMcpConnection ? t('services.common.refreshServerHint') : undefined}
              />
            ) : (
              <div className="space-y-0.5">
                {listedTools.map((tool) => <ToolItem key={tool.id || tool.name} tool={tool} onDecide={handleDecideTool} deciding={decidingHash} />)}
                {removedTools.length > 0 && (
                  <>
                    <SectionLabel className="px-0 pb-1 pt-3">{t('services.toolPin.removedSection', { count: removedTools.length })}</SectionLabel>
                    {removedTools.map((tool) => <ToolItem key={tool.id} tool={tool} onDecide={handleDecideTool} deciding={decidingHash} />)}
                  </>
                )}
              </div>
            )}
          </Card>

          {/* Active tokens for this service */}
          <Card>
            <CardHeader
              title={t('services.detail.tokensTitle', { n: tokens.length })}
              action={<Button variant="ghost" size="xs" to={`/tokens?service_id=${encodeURIComponent(service.id)}`}>{t('services.detail.viewAllTokens')}</Button>}
            />
            {tokens.length === 0 ? (
              <EmptyState compact icon={Key} title={t('services.detail.tokensEmpty')} description={t('services.detail.tokensHint')} />
            ) : (
              <div className="divide-y divide-border">
                {tokens.slice(0, 10).map((tk) => (
                  <div key={tk.jti} className="group py-2.5">
                    <div className="flex items-center gap-3">
                      <Link to={`/tokens/${encodeURIComponent(tk.jti)}`} className="flex min-w-0 flex-1 items-center gap-2">
                        <KindBadge kind={tk.kind} />
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-medium text-foreground transition-colors duration-200 group-hover:text-link">{tk.label || tk.client_name || tk.jti}</span>
                          {/* Personal tokens always belong to the console, so only the expiry is worth a line */}
                          <span className="block truncate text-xs text-muted-foreground">
                            {tk.kind !== 'pat' && (tk.client_name || tk.client_id)}
                            {tk.kind !== 'pat' && tk.expires_at && ' · '}
                            {tk.expires_at && `${t('services.detail.tokenExpires')} ${formatDate(tk.expires_at)}`}
                          </span>
                        </span>
                      </Link>
                      <StatusBadge status={tk.status} />
                      <IconButton
                        variant="destructive"
                        icon={revokingJti === tk.jti ? RefreshCw : Trash2}
                        onClick={() => handleRevokeToken(tk)}
                        disabled={revokingJti === tk.jti}
                        title={t('tokens.list.revokeTitle')}
                        className={clsx('opacity-0 transition-opacity duration-150 focus-visible:opacity-100 group-hover:opacity-100',
                          revokingJti === tk.jti && 'animate-spin opacity-100')}
                      />
                    </div>
                    {/* Scopes on their own line so the long mono chips never fight the
                        row (this card lives in the narrow 1/3 sidebar column, where two
                        chips + status + action cannot share one line). */}
                    {tk.scopes?.length > 0 && (
                      <div className="mt-1.5 pl-[2.75rem]">
                        <ScopeChips scopes={tk.scopes} max={3} />
                      </div>
                    )}
                  </div>
                ))}
                {tokens.length > 10 && <p className="pt-2 text-center text-xs text-muted-foreground tabular-nums">+{tokens.length - 10}</p>}
              </div>
            )}
          </Card>
        </div>
      </div>

      {showEditModal && (
        <ServiceFormModal mode="edit" service={service} scopes={scopes} onClose={() => setShowEditModal(false)} onSubmit={handleUpdate} />
      )}
    </div>
  )
}
