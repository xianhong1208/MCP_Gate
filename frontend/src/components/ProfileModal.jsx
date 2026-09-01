import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../contexts/AuthContext'
import { sessionApi } from '../services/api'
import { useToast } from '../contexts/ToastContext'
import { formatDateTime } from '../utils/format'
import { X, Key, Eye, EyeOff, Check, Pencil } from 'lucide-react'
import {
  Dialog, DialogBody, DialogFooter, Button, IconButton, Input, Field, Alert, Avatar, Badge, DescriptionList,
} from './ui'

export default function ProfileModal({ isOpen, onClose }) {
  const { t } = useTranslation()
  const { user, refreshUser } = useAuth()
  const toast = useToast()
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [editingName, setEditingName] = useState(false)
  const [nameValue, setNameValue] = useState('')
  const [savingName, setSavingName] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' })
  const [showPasswords, setShowPasswords] = useState({ current: false, new: false, confirm: false })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  if (!isOpen) return null

  // Third-party login accounts and accounts without a password do not need the current password
  const needsCurrent = !!user?.has_password

  const handlePasswordChange = async (e) => {
    e.preventDefault()
    setError('')
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setError(t('components.profile.errorPasswordMismatch'))
      return
    }
    if (passwordForm.newPassword.length < 8) {
      setError(t('components.profile.errorPasswordTooShort'))
      return
    }
    setIsSubmitting(true)
    try {
      await sessionApi.changePassword(needsCurrent ? passwordForm.currentPassword : null, passwordForm.newPassword)
      await refreshUser()
      toast.success(t('components.profile.successPasswordChanged'))
      setShowChangePassword(false)
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })
    } catch (err) {
      setError(err.message || t('components.profile.errorPasswordFailed'))
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleSaveName = async () => {
    const newName = nameValue.trim()
    if (!newName || newName === user?.username) {
      setEditingName(false)
      return
    }
    setSavingName(true)
    try {
      await sessionApi.updateProfile(newName)
      await refreshUser()
      toast.success(t('components.profile.successNameChanged'))
      setEditingName(false)
    } catch (err) {
      toast.error(err.message || t('components.profile.errorNameFailed'))
    } finally {
      setSavingName(false)
    }
  }

  const handleClose = () => {
    setShowChangePassword(false)
    setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })
    setEditingName(false)
    setError('')
    onClose()
  }

  const backToProfile = () => {
    setShowChangePassword(false)
    setError('')
    setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })
  }

  // Plain function, not a nested component: a nested component remounts on every render and the input loses focus
  const renderPasswordInput = ({ field, key, label, autoComplete, minLength }) => (
    <Field label={label}>
      <div className="relative">
        <Input
          type={showPasswords[field] ? 'text' : 'password'}
          value={passwordForm[key]}
          onChange={(e) => setPasswordForm({ ...passwordForm, [key]: e.target.value })}
          className="pr-10"
          autoComplete={autoComplete}
          required
          minLength={minLength}
        />
        <IconButton
          size="sm"
          icon={showPasswords[field] ? EyeOff : Eye}
          title={showPasswords[field] ? 'Hide' : 'Show'}
          onClick={() => setShowPasswords({ ...showPasswords, [field]: !showPasswords[field] })}
          className="absolute right-1 top-1/2 -translate-y-1/2"
        />
      </div>
    </Field>
  )

  const title = showChangePassword
    ? (needsCurrent ? t('components.profile.changePasswordTitle') : t('components.profile.setPasswordTitle'))
    : t('components.profile.title')

  return (
    <Dialog open onClose={handleClose} title={title} size="md">
      {!showChangePassword ? (
        <>
          <DialogBody className="space-y-5">
            <div className="flex items-center gap-4">
              <Avatar name={user?.username || user?.email || 'A'} size="lg" />
              <div className="min-w-0 flex-1">
                {editingName ? (
                  <div className="flex items-center gap-1.5">
                    <Input
                      type="text"
                      size="sm"
                      value={nameValue}
                      onChange={(e) => setNameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleSaveName()
                        if (e.key === 'Escape') setEditingName(false)
                      }}
                      maxLength={64}
                      autoFocus
                      className="w-44"
                    />
                    <IconButton icon={Check} title={t('components.profile.saveName')} onClick={handleSaveName} disabled={savingName} className="text-success" />
                    <IconButton icon={X} title={t('components.profile.back')} onClick={() => setEditingName(false)} disabled={savingName} />
                  </div>
                ) : (
                  <div className="flex items-center gap-1">
                    <h3 className="truncate text-base font-semibold text-foreground">
                      {user?.username || t('components.profile.unknownUser')}
                    </h3>
                    <IconButton
                      size="sm"
                      icon={Pencil}
                      title={t('components.profile.editName')}
                      onClick={() => { setNameValue(user?.username || ''); setEditingName(true) }}
                    />
                  </div>
                )}
                <Badge tone="neutral" className="mt-1">
                  {t('components.profile.provider', { provider: t(`components.profile.providers.${user?.auth_provider || 'local'}`, { defaultValue: user?.auth_provider || 'local' }) })}
                </Badge>
              </div>
            </div>

            <DescriptionList
              className="rounded-md border border-border px-4"
              items={[
                { label: t('components.profile.email'), value: user?.email || t('components.profile.emailNotSet') },
                { label: t('components.profile.memberSince'), value: user?.created_at ? formatDateTime(user.created_at) : t('components.profile.memberSinceUnknown') },
                { label: t('components.profile.lastLogin'), value: user?.last_login ? formatDateTime(user.last_login) : t('components.profile.lastLoginCurrent') },
              ]}
            />

            {!needsCurrent && (
              <p className="text-xs text-muted-foreground">{t('components.profile.noPasswordHint')}</p>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="secondary" icon={Key} onClick={() => setShowChangePassword(true)}>
              {needsCurrent ? t('components.profile.changePassword') : t('components.profile.setPassword')}
            </Button>
          </DialogFooter>
        </>
      ) : (
        <form onSubmit={handlePasswordChange} className="flex min-h-0 flex-col">
          <DialogBody className="space-y-4">
            {error && <Alert tone="danger">{error}</Alert>}

            {needsCurrent && renderPasswordInput({ field: 'current', key: 'currentPassword', label: t('components.profile.currentPassword'), autoComplete: 'current-password' })}
            {renderPasswordInput({ field: 'new', key: 'newPassword', label: t('components.profile.newPassword'), autoComplete: 'new-password', minLength: 8 })}
            {renderPasswordInput({ field: 'confirm', key: 'confirmPassword', label: t('components.profile.confirmPassword'), autoComplete: 'new-password' })}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="secondary" onClick={backToProfile}>
              {t('components.profile.back')}
            </Button>
            <Button type="submit" variant="primary" loading={isSubmitting}>
              {isSubmitting ? t('components.profile.saving') : t('components.profile.save')}
            </Button>
          </DialogFooter>
        </form>
      )}
    </Dialog>
  )
}
