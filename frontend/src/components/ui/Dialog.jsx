import { useEffect, useCallback, useId, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import clsx from 'clsx'
import IconButton from './IconButton'

const sizes = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
  '2xl': 'max-w-2xl',
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Dialog — the only overlay container in the app.
 * Structure: overlay (black/60, no blur) + panel (rounded-lg, popover background, crisp shadow, 200 ms fade+slide).
 * Compose the content with DialogHeader / DialogBody / DialogFooter, separated by borders.
 * Passing `title` renders DialogHeader automatically (with the top-right X).
 * Focus is trapped inside the panel while open and restored to the opener on close.
 */
export default function Dialog({
  open = true,
  onClose,
  title,
  description,
  children,
  size = 'md',
  showClose = true,
  className,
  panelClassName,
  zIndex = 'z-[60]',
  scrollable = true,
}) {
  const titleId = useId()
  const panelRef = useRef(null)

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Escape') {
      onClose?.()
      return
    }
    if (e.key !== 'Tab' || !panelRef.current) return
    const focusable = Array.from(panelRef.current.querySelectorAll(FOCUSABLE))
    if (focusable.length === 0) {
      e.preventDefault()
      return
    }
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }, [onClose])

  useEffect(() => {
    if (!open) return undefined
    const opener = document.activeElement
    document.addEventListener('keydown', handleKeyDown)
    document.body.style.overflow = 'hidden'
    // Move focus inside unless a child already asked for it (autoFocus)
    const panel = panelRef.current
    if (panel && !panel.contains(document.activeElement)) {
      const target = panel.querySelector('[autofocus]') || panel.querySelector(FOCUSABLE) || panel
      target.focus?.()
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''
      if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus()
    }
  }, [open, handleKeyDown])

  if (!open) return null

  return (
    <div className={clsx('fixed inset-0 flex items-center justify-center p-4', zIndex, className)} role="dialog" aria-modal="true" aria-labelledby={title ? titleId : undefined}>
      <div className="absolute inset-0 bg-black/60 animate-fade-in" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        tabIndex={-1}
        className={clsx(
          'relative flex w-full flex-col rounded-lg border border-border-strong bg-popover shadow-overlay animate-dialog-in',
          scrollable && 'max-h-[90vh]',
          sizes[size] || sizes.md,
          panelClassName,
        )}
      >
        {(title || showClose) && (
          <DialogHeader id={titleId} title={title} description={description} onClose={showClose ? onClose : undefined} />
        )}
        {children}
      </div>
    </div>
  )
}

export function DialogHeader({ id, title, description, onClose, className, children }) {
  const { t } = useTranslation()
  return (
    <div className={clsx('flex items-start justify-between gap-4 border-b border-border px-5 py-4', className)}>
      <div className="min-w-0">
        {title && <h2 id={id} className="text-base font-semibold text-foreground">{title}</h2>}
        {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        {children}
      </div>
      {onClose && <IconButton icon={X} title={t('common.close')} onClick={onClose} className="-mr-1.5 -mt-1" />}
    </div>
  )
}

export function DialogBody({ className, children }) {
  return <div className={clsx('min-h-0 flex-1 overflow-y-auto px-5 py-5', className)}>{children}</div>
}

export function DialogFooter({ className, children, between = false }) {
  return (
    <div className={clsx('flex items-center gap-2 border-t border-border px-5 py-3', between ? 'justify-between' : 'justify-end', className)}>
      {children}
    </div>
  )
}
