import { AlertCircle, CheckCircle2, Info, AlertTriangle } from 'lucide-react'
import clsx from 'clsx'

/** Every semantic tone is "tinted bg (/10) + same-hue border (/20) + primary text"; the icon uses the tone color */
const tones = {
  danger: {
    icon: AlertCircle,
    className: 'border-danger/30 bg-danger/10 text-foreground',
    iconClass: 'text-danger',
  },
  warning: {
    icon: AlertTriangle,
    className: 'border-warning/30 bg-warning/10 text-foreground',
    iconClass: 'text-warning',
  },
  success: {
    icon: CheckCircle2,
    className: 'border-success/30 bg-success/10 text-foreground',
    iconClass: 'text-success',
  },
  info: {
    icon: Info,
    className: 'border-info/30 bg-info/10 text-foreground',
    iconClass: 'text-info',
  },
  neutral: {
    icon: Info,
    className: 'border-border bg-muted/60 text-foreground',
    iconClass: 'text-muted-foreground',
  },
}

/** Inline message box: tinted background + same-hue border + icon */
export default function Alert({ tone = 'danger', title, icon, className, children, action }) {
  const cfg = tones[tone] || tones.danger
  const Icon = icon === null ? null : icon || cfg.icon
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={clsx('flex items-start gap-3 rounded-md border px-3.5 py-3 text-sm', cfg.className, className)}>
      {Icon && <Icon className={clsx('mt-0.5 h-4 w-4 shrink-0', cfg.iconClass)} aria-hidden="true" />}
      <div className="min-w-0 flex-1">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={clsx(title && 'mt-0.5 text-muted-foreground', 'text-[13px] leading-relaxed')}>{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}
