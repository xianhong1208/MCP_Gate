import { useTranslation } from 'react-i18next'
import clsx from 'clsx'
import { StatusPill } from './ui'

const HEALTH_TONE = { online: 'success', offline: 'danger', error: 'warning', unknown: 'neutral' }

/** Translated health pill shared by the services list and the service detail page. */
export default function HealthIndicator({ status, className }) {
  const { t } = useTranslation()
  const key = HEALTH_TONE[status] ? status : 'unknown'
  return (
    <StatusPill tone={HEALTH_TONE[key]} className={clsx(className)}>
      {t(`dashboard.serviceHealth.${key}`)}
    </StatusPill>
  )
}
