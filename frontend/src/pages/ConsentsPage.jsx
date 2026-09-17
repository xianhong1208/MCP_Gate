import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Search, RefreshCw, Trash2 } from 'lucide-react'
import clsx from 'clsx'
import { formatDateTime } from '../utils/format'
import { oauthApi } from '../services/api'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import { ScopeChips } from './TokensPage'
import {
  PageHeader, IconButton, Card, Alert, EmptyState, LoadingBlock, SearchInput,
  Table, THead, TBody, TR, TH, TD, RowActions,
} from '../components/ui'

/**
 * Remembered consents: the (client, server) pairs for which the signed-in owner ticked
 * "remember this decision". Forgetting one makes the client go through the consent screen again.
 *
 * The API is scoped to the signed-in user on both list and delete, so this page never has to
 * think about ownership.
 */
export default function ConsentsPage() {
  const { t } = useTranslation()
  const { confirm } = useConfirm()
  const toast = useToast()

  const [consents, setConsents] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [forgetting, setForgetting] = useState(null)

  const loadData = useCallback(async ({ silent = false } = {}) => {
    if (!silent) {
      setIsLoading(true)
      setError(null)
    }
    try {
      const res = await oauthApi.consents.list()
      setConsents(res.consents || [])
    } catch (err) {
      setError(err.message || t('consents.list.loadFail'))
    } finally {
      if (!silent) setIsLoading(false)
    }
  }, [t])

  useEffect(() => { loadData() }, [loadData])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return consents
    return consents.filter((c) =>
      c.client_name?.toLowerCase().includes(q) ||
      c.client_id?.toLowerCase().includes(q) ||
      c.audience?.toLowerCase().includes(q) ||
      (c.scopes || []).some((s) => s.toLowerCase().includes(q)))
  }, [consents, search])

  const handleForget = async (c) => {
    const name = c.client_name || c.client_id
    const ok = await confirm({
      title: t('consents.list.forgetTitle'),
      message: t('confirm.deleteMessage', { item: t('consents.list.forgetTarget', { name }) }),
      confirmText: t('consents.list.forgetTitle'),
      cancelText: t('confirm.cancel'),
      type: 'delete',
    })
    if (!ok) return
    setForgetting(c.id)
    try {
      await oauthApi.consents.delete(c.id)
      toast.success(t('consents.list.forgetSuccess'))
      await loadData({ silent: true })
    } catch (err) {
      toast.error(t('consents.list.forgetFail', { message: err.message }))
    } finally {
      setForgetting(null)
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('consents.list.title')}
        description={t('consents.list.subtitle')}
        actions={
          <IconButton
            variant="secondary"
            icon={RefreshCw}
            title={t('consents.list.refresh')}
            onClick={() => loadData()}
            disabled={isLoading}
            className={clsx(isLoading && 'animate-spin')}
          />
        }
      />

      {error && <Alert tone="danger">{error}</Alert>}

      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          icon={Search}
          size="sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t('consents.list.searchPlaceholder')}
          className="min-w-[220px] flex-1"
        />
        {consents.length > 0 && (
          <span className="text-xs text-muted-foreground tabular-nums">{t('consents.list.count', { count: filtered.length })}</span>
        )}
      </div>

      {isLoading ? (
        <LoadingBlock />
      ) : filtered.length === 0 ? (
        <Card padding="none">
          <EmptyState
            icon={ShieldCheck}
            title={t('consents.list.empty')}
            description={search ? t('consents.list.adjustFilters') : t('consents.list.emptyHint')}
          />
        </Card>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          <Table bordered={false}>
            <THead>
              <TR hover={false} group={false}>
                <TH>{t('consents.list.colClient')}</TH>
                <TH>{t('consents.list.colAudience')}</TH>
                <TH>{t('consents.list.colScopes')}</TH>
                <TH className="hidden xl:table-cell">{t('consents.list.colGranted')}</TH>
                <TH align="right" className="w-16"><span className="sr-only">{t('consents.list.colActions')}</span></TH>
              </TR>
            </THead>
            <TBody>
              {filtered.map((c) => (
                <TR key={c.id}>
                  <TD className="max-w-[240px]">
                    <Link to="/clients" className="block truncate font-medium text-foreground transition-colors duration-200 hover:text-link" title={c.client_id}>
                      {c.client_name || c.client_id}
                    </Link>
                    {c.client_name && (
                      <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={c.client_id}>{c.client_id}</p>
                    )}
                  </TD>
                  <TD className="max-w-[280px]">
                    {c.audience ? (
                      <span className="block truncate font-mono text-xs text-foreground" title={c.audience}>{c.audience}</span>
                    ) : (
                      <span className="text-xs text-subtle-foreground">{t('consents.list.noAudience')}</span>
                    )}
                  </TD>
                  <TD><ScopeChips scopes={c.scopes} max={4} /></TD>
                  <TD className="hidden whitespace-nowrap xl:table-cell" muted>{c.granted_at ? formatDateTime(c.granted_at) : '—'}</TD>
                  <TD align="right">
                    <RowActions>
                      <IconButton
                        variant="destructive"
                        icon={forgetting === c.id ? RefreshCw : Trash2}
                        title={t('consents.list.forgetTitle')}
                        onClick={() => handleForget(c)}
                        disabled={forgetting === c.id}
                        className={clsx(forgetting === c.id && 'animate-spin')}
                      />
                    </RowActions>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
    </div>
  )
}
