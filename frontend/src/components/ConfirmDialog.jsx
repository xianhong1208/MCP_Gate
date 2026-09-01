import { useTranslation } from 'react-i18next'
import { AlertTriangle, Trash2, Ban, Info } from 'lucide-react'
import clsx from 'clsx'
import Dialog, { DialogFooter } from './ui/Dialog'
import Button from './ui/Button'

const iconMap = {
  danger: { icon: AlertTriangle, className: 'bg-danger/10 text-danger', button: 'destructiveSolid' },
  delete: { icon: Trash2, className: 'bg-danger/10 text-danger', button: 'destructiveSolid' },
  warning: { icon: AlertTriangle, className: 'bg-warning/10 text-warning', button: 'destructiveSolid' },
  revoke: { icon: Ban, className: 'bg-warning/10 text-warning', button: 'destructiveSolid' },
  info: { icon: Info, className: 'bg-info/10 text-info', button: 'primary' },
}

export default function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText,
  cancelText,
  type = 'danger', // danger, warning, info, delete, revoke
  isLoading = false,
}) {
  const { t } = useTranslation()
  if (!isOpen) return null

  // Defaults come from i18n; they cannot be function defaults because the hook must run first
  const resolvedTitle = title || t('components.confirm.title')
  const resolvedConfirmText = confirmText || t('components.confirm.confirm')
  const resolvedCancelText = cancelText || t('components.confirm.cancel')

  const cfg = iconMap[type] || iconMap.danger
  const Icon = cfg.icon

  const handleConfirm = () => {
    onConfirm()
  }

  return (
    <Dialog open onClose={onClose} size="sm" showClose={false} zIndex="z-[100]">
      <div className="px-5 pt-5 pb-4">
        <div className="flex items-start gap-4">
          <div className={clsx('flex h-10 w-10 shrink-0 items-center justify-center rounded-md', cfg.className)}>
            <Icon className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0 pt-0.5">
            <h2 className="text-base font-semibold text-foreground">{resolvedTitle}</h2>
            <p className="mt-1.5 whitespace-pre-line text-sm leading-relaxed text-muted-foreground">{message}</p>
          </div>
        </div>
      </div>
      <DialogFooter>
        <Button variant="secondary" onClick={onClose} disabled={isLoading} autoFocus>
          {resolvedCancelText}
        </Button>
        <Button variant={cfg.button} onClick={handleConfirm} loading={isLoading}>
          {resolvedConfirmText}
        </Button>
      </DialogFooter>
    </Dialog>
  )
}
