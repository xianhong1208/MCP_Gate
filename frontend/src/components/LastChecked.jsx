import { useTranslation } from 'react-i18next'
import { Clock } from 'lucide-react'
import clsx from 'clsx'
import { relativeTimeParts } from '../utils/format'

/**
 * "Last health check" as relative time (e.g. 3 minutes ago); hover shows the absolute time.
 * Renders nothing when there is no data, so callers need not null-check.
 */
export default function LastChecked({ value, withIcon = true, className = '' }) {
  const { t } = useTranslation()
  const parts = relativeTimeParts(value)
  if (!parts) return null
  return (
    <span
      className={clsx('inline-flex items-center gap-1 whitespace-nowrap text-xs text-muted-foreground tabular-nums', className)}
      title={`${t('services.list.lastChecked')}: ${value}`}
    >
      {withIcon && <Clock className="h-3 w-3" aria-hidden="true" />}
      {t(`common.relative.${parts.key}`, { n: parts.n })}
    </span>
  )
}
