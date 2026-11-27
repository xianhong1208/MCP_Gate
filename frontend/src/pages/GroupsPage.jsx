import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Check, ChevronDown, Pencil, Plus, Trash2, UserMinus, UserPlus, Users } from 'lucide-react'
import clsx from 'clsx'
import { groupsApi, usersApi } from '../services/api'
import { useConfirm } from '../contexts/ConfirmContext'
import { useToast } from '../contexts/ToastContext'
import { addableMembers } from '../utils/access'
import {
  PageHeader, Button, IconButton, Badge, Card, EmptyState, LoadingBlock, Alert, Dialog, DialogBody, DialogFooter,
  Field, Input, Select, SectionLabel, Avatar,
} from '../components/ui'

function GroupFormDialog({ group, onClose, onSubmit }) {
  const { t } = useTranslation()
  const [name, setName] = useState(group?.name || '')
  const [description, setDescription] = useState(group?.description || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const save = async () => {
    if (!name.trim()) return
    setSaving(true)
    setError('')
    try {
      await onSubmit({ name: name.trim(), description: description.trim() })
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }
  return (
    <Dialog onClose={onClose} title={t(group ? 'groups.form.editTitle' : 'groups.form.addTitle')}>
      <DialogBody className="space-y-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <Field label={t('groups.form.nameLabel')} required help={t('groups.form.nameHelp')}>
          <Input value={name} maxLength={256} onChange={(e) => setName(e.target.value)} placeholder={t('groups.form.namePlaceholder')} autoFocus data-testid="group-name" />
        </Field>
        <Field label={t('groups.form.descriptionLabel')}>
          <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t('groups.form.descriptionPlaceholder')} />
        </Field>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button variant="primary" size="sm" icon={Check} loading={saving} disabled={!name.trim()} onClick={save} data-testid="group-save">{t('common.save')}</Button>
      </DialogFooter>
    </Dialog>
  )
}

/** One group, expanded: members (add / remove) and the rules that name it. */
function GroupDetail({ groupId, users, onChanged }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [group, setGroup] = useState(null)
  const [adding, setAdding] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setGroup(await groupsApi.get(groupId))
  }, [groupId])
  useEffect(() => { load().catch((err) => toast.error(err.message)) }, [load, toast])

  if (!group) return <LoadingBlock className="py-6" size="sm" />
  const candidates = addableMembers(users, group.members)

  const add = async () => {
    if (!adding) return
    setBusy(true)
    try {
      const res = await groupsApi.addMember(groupId, adding)
      setGroup(res.group)
      setAdding('')
      toast.success(t('groups.memberAdded'))
      onChanged()
    } catch (err) {
      toast.error(err.message)
    } finally {
      setBusy(false)
    }
  }
  const remove = async (m) => {
    try {
      const res = await groupsApi.removeMember(groupId, m.user_id)
      setGroup(res.group)
      toast.success(t('groups.memberRemoved', { name: m.email || m.username }))
      onChanged()
    } catch (err) {
      toast.error(err.message)
    }
  }

  return (
    <div className="grid grid-cols-1 gap-5 border-t border-border pt-4 md:grid-cols-2" data-testid="group-detail">
      <section className="min-w-0 space-y-2">
        <SectionLabel>{t('groups.members', { count: group.members.length })}</SectionLabel>
        {group.members.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t('groups.noMembers')}</p>
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border">
            {group.members.map((m) => (
              <li key={m.user_id} className="flex items-center gap-2.5 px-3 py-2">
                <Avatar name={m.username || m.email || '?'} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-foreground">{m.email || m.user_id}</span>
                  {m.username && <span className="block truncate text-xs text-muted-foreground">{m.username}</span>}
                </span>
                {m.is_active === false && <Badge tone="neutral">{t('groups.inactive')}</Badge>}
                <IconButton variant="destructive" icon={UserMinus} title={t('groups.removeMember')} onClick={() => remove(m)} />
              </li>
            ))}
          </ul>
        )}
        {candidates.length > 0 ? (
          <div className="flex items-center gap-2">
            <Select size="sm" value={adding} onChange={(e) => setAdding(e.target.value)} className="min-w-0 flex-1" data-testid="group-add-member">
              <option value="">{t('groups.chooseMember')}</option>
              {candidates.map((u) => <option key={u.id} value={u.id}>{u.email}{u.username ? ` (${u.username})` : ''}</option>)}
            </Select>
            <Button variant="secondary" size="sm" icon={UserPlus} disabled={!adding} loading={busy} onClick={add}>{t('groups.addMember')}</Button>
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">{t('groups.everyoneIn')}</p>
        )}
      </section>
      <section className="min-w-0 space-y-2">
        <SectionLabel>{t('groups.usedBy', { count: group.rules.length })}</SectionLabel>
        {group.rules.length === 0 ? (
          <p className="text-xs text-muted-foreground">{t('groups.notUsed')}</p>
        ) : (
          <ul className="space-y-1.5">
            {group.rules.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-1.5 text-sm">
                <Badge tone={r.effect === 'deny' ? 'danger' : 'info'}>{t(`access.rules.effect.${r.effect}`)}</Badge>
                <Link to={`/services/${encodeURIComponent(r.service_id)}?tab=access`} className="text-link transition-colors duration-200 hover:text-link-hover">{r.service_name || r.service_id}</Link>
                <span className="min-w-0 break-all font-mono text-xs text-muted-foreground">{r.tools.includes('*') ? t('access.rules.allTools') : r.tools.join(', ')}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">{t('groups.howRulesApply')}</p>
      </section>
    </div>
  )
}

/** Groups of console accounts that tool access rules can name (#37). */
export default function GroupsPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const { confirmDelete } = useConfirm()
  const [groups, setGroups] = useState(null)
  const [users, setUsers] = useState([])
  const [open, setOpen] = useState(null)
  const [form, setForm] = useState(null)   // {} = new, group = edit
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    const [g, u] = await Promise.all([groupsApi.list(), usersApi.list().catch(() => ({ users: [] }))])
    setGroups(g.groups || [])
    setUsers(u.users || [])
  }, [])
  useEffect(() => { load().catch((err) => setError(err.message)) }, [load])

  const submit = async (fields) => {
    if (form?.id) {
      await groupsApi.update(form.id, fields)
      toast.success(t('groups.saved'))
    } else {
      const g = await groupsApi.create(fields)
      setOpen(g.id)
      toast.success(t('groups.created'))
    }
    await load()
  }

  const remove = async (g) => {
    if (!(await confirmDelete(t('groups.deleteTarget', { name: g.name })))) return
    try {
      await groupsApi.delete(g.id)
      toast.success(t('groups.deleted'))
      await load()
    } catch (err) {
      // 409 groups.in_use: open it so the rules that name it are in view
      if (err.code === 'groups.in_use') setOpen(g.id)
      toast.error(err.message)
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title={t('groups.title')}
        description={t('groups.subtitle')}
        actions={<Button variant="primary" icon={Plus} onClick={() => setForm({})} data-testid="add-group">{t('groups.add')}</Button>}
      />
      {error && <Alert tone="danger">{error}</Alert>}
      {groups === null ? (
        !error && <LoadingBlock className="min-h-[200px]" />
      ) : groups.length === 0 ? (
        <Card><EmptyState icon={Users} title={t('groups.empty')} description={t('groups.emptyHint')} action={<Button variant="secondary" icon={Plus} onClick={() => setForm({})}>{t('groups.add')}</Button>} /></Card>
      ) : (
        <div className="space-y-3">
          {groups.map((g) => {
            const isOpen = open === g.id
            return (
              <Card key={g.id} padding="sm" data-testid={`group-${g.name}`}>
                <div className="flex items-start gap-3">
                  <button type="button" onClick={() => setOpen(isOpen ? null : g.id)} aria-expanded={isOpen} className="flex min-w-0 flex-1 items-start gap-3 text-left">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-muted text-subtle-foreground">
                      <Users className="h-4 w-4" aria-hidden="true" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block break-words text-sm font-semibold text-foreground">{g.name}</span>
                      {g.description && <span className="block break-words text-xs text-muted-foreground">{g.description}</span>}
                      <span className="mt-1 flex flex-wrap gap-1.5">
                        <Badge tone="neutral">{t('groups.memberCount', { count: g.member_count })}</Badge>
                        <Badge tone={g.rules_count ? 'accent' : 'neutral'}>{t('groups.ruleCount', { count: g.rules_count })}</Badge>
                      </span>
                    </span>
                    <ChevronDown className={clsx('mt-1 h-4 w-4 shrink-0 text-subtle-foreground transition-transform duration-200', isOpen && 'rotate-180')} aria-hidden="true" />
                  </button>
                  <div className="flex shrink-0 items-center gap-0.5">
                    <IconButton icon={Pencil} title={t('common.edit')} onClick={() => setForm(g)} />
                    <IconButton variant="destructive" icon={Trash2} title={t('common.delete')} onClick={() => remove(g)} data-testid={`delete-group-${g.name}`} />
                  </div>
                </div>
                {isOpen && <div className="mt-4"><GroupDetail groupId={g.id} users={users} onChanged={load} /></div>}
              </Card>
            )
          })}
        </div>
      )}
      {form && <GroupFormDialog group={form.id ? form : null} onClose={() => setForm(null)} onSubmit={submit} />}
    </div>
  )
}
