import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Download, ExternalLink, KeyRound, LogIn, MousePointerClick } from 'lucide-react'
import { clientConfigApi } from '../services/api'
import { CLIENTS, downloadFile, patNames, stepKeys } from '../utils/clientConfig'
import CodeBlock from './CodeBlock'
import { Alert, Button, LoadingBlock, SegmentedControl, Tabs } from './ui'

/**
 * "Connect a client" (#36): Claude Code, Cursor, VS Code and Codex configuration for one MCP server
 * (`serviceId`) or for every server the console lists (`serviceId` null). Sign-in through MCP Gate (OAuth) by
 * default; the personal-access-token variant references an environment variable or a prompt, never a token.
 */
export default function ClientConfigPanel({ serviceId = null }) {
  const { t } = useTranslation()
  const [client, setClient] = useState('claude-code')
  const [variant, setVariant] = useState('oauth')
  const [config, setConfig] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    setConfig(null)
    setError(null)
    clientConfigApi.get(serviceId, client, variant)
      .then((c) => { if (alive) setConfig(c) })
      .catch((e) => { if (alive) setError(e.message || t('clientConfig.loadFailed')) })
    return () => { alive = false }
  }, [serviceId, client, variant, t])

  const tokenLink = serviceId ? `/tokens/create?service_id=${encodeURIComponent(serviceId)}` : '/tokens/create'
  const names = patNames(config)
  const vars = {
    path: config?.file?.path || '',
    env: names.join(', '),
    count: config?.servers?.length || 0,
  }

  return (
    <div className="space-y-4" data-testid="client-config">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 overflow-x-auto sm:flex-1">
          <Tabs
            size="sm"
            value={client}
            onChange={setClient}
            items={CLIENTS.map((c) => ({ key: c.key, label: c.label }))}
          />
        </div>
        <SegmentedControl
          size="sm"
          className="self-start sm:self-auto"
          value={variant}
          onChange={setVariant}
          items={[
            { key: 'oauth', label: t('clientConfig.variant.oauth'), icon: LogIn },
            { key: 'pat', label: t('clientConfig.variant.pat'), icon: KeyRound },
          ]}
        />
      </div>

      {error && <Alert tone="danger">{error}</Alert>}
      {!error && !config && <LoadingBlock />}
      {config && (
        <>
          {variant === 'pat' ? (
            <Alert tone="info" title={t('clientConfig.patTitle')}>
              {t('clientConfig.patBody')}{' '}
              <Link to={tokenLink} className="font-medium text-foreground underline underline-offset-2">
                {t('clientConfig.createPat')}
              </Link>
            </Alert>
          ) : (
            <p className="text-sm text-muted-foreground">{t('clientConfig.oauthIntro')}</p>
          )}

          {config.servers.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('clientConfig.noServers')}</p>
          ) : (
            <>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-foreground marker:text-muted-foreground">
                {stepKeys(client, variant).map((k) => (
                  <li key={k} className="break-words">{t(`clientConfig.steps.${k}`, vars)}</li>
                ))}
              </ol>

              {config.install_links.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {config.install_links.map((href, i) => (
                    <Button key={href} href={href} variant="primary" size="sm" icon={MousePointerClick}>
                      {config.servers.length > 1
                        ? t('clientConfig.addToCursorNamed', { name: config.servers[i].name })
                        : t('clientConfig.addToCursor')}
                    </Button>
                  ))}
                </div>
              )}

              {config.commands.length > 0 && (
                <CodeBlock title={t('clientConfig.commandsTitle')} language="bash" value={config.commands.join('\n')} rows={10} />
              )}

              <div className="space-y-2">
                <CodeBlock title={config.file.path} language={config.file.format} value={config.file.content} rows={18} />
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <a
                    href={config.docs_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                  >
                    {t('clientConfig.docs', { client: CLIENTS.find((c) => c.key === client)?.label })}
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  </a>
                  <Button size="sm" variant="secondary" icon={Download} onClick={() => downloadFile(config.file)}>
                    {t('clientConfig.download', { filename: config.file.filename })}
                  </Button>
                </div>
              </div>

              {variant === 'oauth' && config.dcr_auto_approve === false && (
                <Alert tone="warning">{t('clientConfig.dcrReview')}</Alert>
              )}
            </>
          )}

          {config.skipped && config.skipped.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {t('clientConfig.skipped', { names: config.skipped.join(', ') })}
            </p>
          )}
        </>
      )}
    </div>
  )
}
