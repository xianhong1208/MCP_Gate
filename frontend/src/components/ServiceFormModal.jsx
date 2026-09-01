import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Check } from 'lucide-react'
import clsx from 'clsx'
import {
  Dialog, DialogBody, DialogFooter, Button, Field, Input, Select, Textarea, CheckRow, Checkbox, Alert, SectionLabel,
} from './ui'

/**
 * Shared form for registering / editing an MCP service.
 *
 * onSubmit(fields) receives the camelCase fields of servicesApi.create / update:
 *   { name?, description, host, port, protocol, mcpPath, tags, requiresAuth, oauthAudience, oauthScopes, authToken? }
 *   - oauthAudience '' = clear (fall back to the MCP URL); oauthScopes [] = unrestricted
 *   - authToken is only sent when the user typed one or ticked "clear" (edit), to avoid overwriting the existing value
 */
export default function ServiceFormModal({ mode = 'create', service = null, scopes = [], onClose, onSubmit }) {
  const { t } = useTranslation()
  const isEdit = mode === 'edit'
  const [form, setForm] = useState({
    name: service?.name || '',
    description: service?.description || '',
    host: service?.host || '',
    port: service?.port || '',
    protocol: service?.protocol || 'http',
    mcpPath: service?.mcp_path || '/mcp',
    tags: service?.tags?.join(', ') || '',
    requiresAuth: service ? !!service.requires_auth : true,
    oauthAudience: service?.oauth_audience || '',
    oauthScopes: new Set(service?.oauth_scopes || []),
    authToken: '',
    clearAuthToken: false,
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const set = (patch) => setForm((prev) => ({ ...prev, ...patch }))
  const toggleScope = (name) => {
    const next = new Set(form.oauthScopes)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    set({ oauthScopes: next })
  }

  // The effective audience shown to the user: custom value, otherwise the MCP URL
  const previewUrl = form.host && form.port
    ? `${form.protocol}://${form.host}:${form.port}${form.mcpPath || '/mcp'}`
    : ''
  const audiencePlaceholder = previewUrl || service?.effective_audience || t('services.form.oauthAudiencePlaceholder')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)
    try {
      const fields = {
        description: form.description,
        host: form.host || null,
        port: form.port ? parseInt(form.port, 10) : null,
        protocol: form.protocol,
        mcpPath: form.mcpPath || '/mcp',
        tags: form.tags ? form.tags.split(',').map((x) => x.trim()).filter(Boolean) : [],
        requiresAuth: form.requiresAuth,
        oauthAudience: form.oauthAudience.trim(),
        oauthScopes: [...form.oauthScopes],
      }
      if (!isEdit) {
        fields.name = form.name.trim()
        if (form.authToken) fields.authToken = form.authToken
      } else if (form.clearAuthToken) {
        fields.authToken = ''
      } else if (form.authToken) {
        fields.authToken = form.authToken
      }
      await onSubmit(fields)
      onClose()
    } catch (err) {
      setError(err.message || (isEdit ? t('services.edit.updateFailed') : t('services.create.createFailed')))
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={isEdit ? t('services.edit.title', { name: service?.name }) : t('services.create.title')}
    >
      <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col">
        <DialogBody className="space-y-6">
          {error && <Alert tone="danger">{error}</Alert>}

          <div className="grid gap-5">
            {!isEdit && (
              <Field label={t('services.create.name')} required>
                <Input
                  type="text"
                  value={form.name}
                  onChange={(e) => set({ name: e.target.value })}
                  placeholder={t('services.create.namePlaceholder')}
                  pattern="[a-zA-Z0-9_\-]+"
                  required
                  autoFocus
                />
              </Field>
            )}

            <Field label={t('services.common.description')}>
              <Textarea
                value={form.description}
                onChange={(e) => set({ description: e.target.value })}
                rows={2}
                placeholder={t('services.common.descriptionPlaceholder')}
              />
            </Field>
          </div>

          {/* MCP connection */}
          <section className="space-y-4 border-t border-border pt-5">
            <SectionLabel>{t('services.common.mcpConnection')}</SectionLabel>
            <div className="grid grid-cols-2 gap-5">
              <Field label={t('services.common.host')}>
                <Input type="text" value={form.host} onChange={(e) => set({ host: e.target.value })} placeholder="localhost" />
              </Field>
              <Field label={t('services.common.port')}>
                <Input type="number" value={form.port} onChange={(e) => set({ port: e.target.value })} placeholder="8000" />
              </Field>
              <Field label={t('services.common.protocol')}>
                <Select value={form.protocol} onChange={(e) => set({ protocol: e.target.value })}>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </Select>
              </Field>
              <Field label={t('services.common.mcpPath')}>
                <Input type="text" value={form.mcpPath} onChange={(e) => set({ mcpPath: e.target.value })} placeholder="/mcp" mono />
              </Field>
            </div>
            <Field label={t('services.common.tagsCommaSeparated')}>
              <Input type="text" value={form.tags} onChange={(e) => set({ tags: e.target.value })} placeholder={t('services.common.tagsPlaceholder')} />
            </Field>
          </section>

          {/* OAuth */}
          <section className="space-y-4 border-t border-border pt-5">
            <div>
              <SectionLabel>{t('services.form.oauthSection')}</SectionLabel>
              <p className="mt-1 text-xs text-muted-foreground">{t('services.form.oauthSectionHint')}</p>
            </div>

            <CheckRow
              checked={form.requiresAuth}
              onChange={(e) => set({ requiresAuth: e.target.checked })}
              label={t('services.form.requiresAuth')}
              description={t('services.form.requiresAuthHint')}
            />

            <Field label={t('services.form.oauthAudience')} help={t('services.form.oauthAudienceHint')}>
              <Input
                type="text"
                value={form.oauthAudience}
                onChange={(e) => set({ oauthAudience: e.target.value })}
                placeholder={audiencePlaceholder}
                mono
              />
            </Field>

            <Field
              label={t('services.form.oauthScopes')}
              help={scopes.length === 0
                ? t('services.form.noScopesDefined')
                : form.oauthScopes.size === 0 ? t('services.form.oauthScopesAll') : t('services.form.oauthScopesHint')}
            >
              {scopes.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {scopes.map((s) => {
                    const on = form.oauthScopes.has(s.name)
                    return (
                      <button
                        key={s.name}
                        type="button"
                        onClick={() => toggleScope(s.name)}
                        title={s.description || ''}
                        aria-pressed={on}
                        className={clsx(
                          'inline-flex h-7 items-center gap-1 rounded-md border px-2 font-mono text-xs transition-colors duration-200',
                          on
                            ? 'border-primary bg-primary text-primary-foreground'
                            : 'border-border-strong bg-card text-muted-foreground hover:border-subtle-foreground hover:text-foreground',
                        )}
                      >
                        {on && <Check className="h-3 w-3" aria-hidden="true" />}
                        {s.name}
                      </button>
                    )
                  })}
                </div>
              )}
            </Field>
          </section>

          {/* Static bearer (external service with its own token) */}
          <section className="space-y-4 border-t border-border pt-5">
            <div>
              <SectionLabel>{t('services.form.staticToken')}</SectionLabel>
              <p className="mt-1 text-xs text-muted-foreground">{t('services.form.staticTokenHint')}</p>
            </div>
            <Input
              type="password"
              value={form.authToken}
              onChange={(e) => set({ authToken: e.target.value, clearAuthToken: false })}
              autoComplete="off"
              placeholder={isEdit && service?.has_static_token ? t('services.form.staticTokenKeep') : t('services.form.staticTokenPlaceholder')}
              disabled={form.clearAuthToken}
              mono
            />
            {isEdit && service?.has_static_token && (
              <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
                <Checkbox
                  checked={form.clearAuthToken}
                  onChange={(e) => set({ clearAuthToken: e.target.checked, authToken: '' })}
                />
                {t('services.form.staticTokenClear')}
              </label>
            )}
          </section>
        </DialogBody>

        <DialogFooter>
          <Button type="button" variant="secondary" onClick={onClose}>{t('services.common.cancel')}</Button>
          <Button type="submit" variant="primary" loading={isLoading} disabled={!isEdit && !form.name}>
            {isLoading
              ? (isEdit ? t('services.edit.submitting') : t('services.create.submitting'))
              : (isEdit ? t('services.edit.submit') : t('services.create.submit'))}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  )
}
