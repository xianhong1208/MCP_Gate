import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Check, Pencil, Trash2 } from 'lucide-react'
import { describeScope } from '../utils/scopes'
import {
  Button, IconButton, Badge, Card, CardHeader, LoadingBlock, Input, Checkbox, RowActions,
} from './ui'

/**
 * Card with an inline editor for a list of scopes ({name, description, is_default}). Used for the global
 * registry (OAuth Clients page) and for the scopes one server declares (service detail page); the caller
 * owns the data and passes `onSave({name, description, isDefault, isNew})` / `onDelete(name)`.
 */
export default function ScopeEditor({ title, description, scopes, isLoading, onSave, onDelete, emptyText, badge }) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(null)   // {name, description, isDefault, isNew}
  const [saving, setSaving] = useState(false)

  const save = async () => {
    if (!editing?.name.trim()) return
    setSaving(true)
    try {
      const ok = await onSave({ ...editing, name: editing.name.trim() })
      if (ok !== false) setEditing(null)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader
        title={title}
        description={description}
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
        <p className="rounded-md border border-dashed border-border px-3 py-2.5 text-xs text-muted-foreground">{emptyText || t('clients.scopes.empty')}</p>
      ) : (
        <div className="divide-y divide-border">
          {scopes.map((s) => (
            <div key={s.name} className="group flex items-center justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <p className="flex items-center gap-2 font-mono text-xs font-medium text-foreground">
                  {s.name}
                  {s.is_default && <Badge tone="success">{t('clients.scopes.default')}</Badge>}
                  {badge && <Badge tone="accent">{badge}</Badge>}
                </p>
                <p className="truncate text-xs text-muted-foreground">{describeScope(t, s.name, s.description) || t('clients.scopes.noDescription')}</p>
              </div>
              <RowActions>
                <IconButton
                  icon={Pencil}
                  onClick={() => setEditing({ name: s.name, description: s.description || '', isDefault: !!s.is_default, isNew: false })}
                  title={t('clients.scopes.edit')}
                />
                <IconButton variant="destructive" icon={Trash2} onClick={() => onDelete(s.name)} title={t('clients.scopes.delete')} />
              </RowActions>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
