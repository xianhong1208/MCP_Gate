import { useTranslation } from 'react-i18next'
import { useTheme } from '../contexts/ThemeContext'
import { Sun, Moon } from 'lucide-react'
import IconButton from './ui/IconButton'

export default function ThemeToggle() {
  const { t } = useTranslation()
  const { theme, toggleTheme } = useTheme()

  return (
    <IconButton
      icon={theme === 'dark' ? Sun : Moon}
      onClick={toggleTheme}
      title={theme === 'dark' ? t('common.theme.switchToLight') : t('common.theme.switchToDark')}
    />
  )
}
