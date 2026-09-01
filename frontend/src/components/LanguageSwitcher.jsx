import { useTranslation } from 'react-i18next'
import { Languages } from 'lucide-react'
import IconButton from './ui/IconButton'

const LANGUAGES = [
  { code: 'en', label: 'EN' },
  { code: 'zh-TW', label: '中文' },
]

export default function LanguageSwitcher() {
  const { i18n, t } = useTranslation()
  const current = i18n.resolvedLanguage || 'en'

  const cycle = () => {
    const idx = LANGUAGES.findIndex(l => l.code === current)
    const next = LANGUAGES[(idx + 1) % LANGUAGES.length]
    i18n.changeLanguage(next.code)
  }

  const currentLabel = LANGUAGES.find(l => l.code === current)?.label || 'EN'

  return (
    <IconButton
      icon={Languages}
      onClick={cycle}
      title={`${t('common.language')} · ${currentLabel}`}
    />
  )
}
