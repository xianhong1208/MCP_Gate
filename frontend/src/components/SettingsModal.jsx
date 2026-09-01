import { useTranslation } from 'react-i18next'
import { RotateCcw, Sun, Moon } from 'lucide-react'
import { usePreferences } from '../contexts/PreferencesContext'
import { useTheme } from '../contexts/ThemeContext'
import { Dialog, DialogBody, DialogFooter, Button, Field, Select, SegmentedControl } from './ui'

export default function SettingsModal({ isOpen, onClose }) {
  const { t } = useTranslation()
  const { preferences, updatePreference, resetPreferences } = usePreferences()
  const { theme, setTheme } = useTheme()

  if (!isOpen) return null

  return (
    <Dialog open onClose={onClose} title={t('components.settings.title')} size="md">
      <DialogBody className="space-y-5">
        <Field label={t('components.settings.theme')}>
          <SegmentedControl
            value={theme}
            onChange={setTheme}
            items={[
              { key: 'light', label: t('components.settings.themeLight'), icon: Sun },
              { key: 'dark', label: t('components.settings.themeDark'), icon: Moon },
            ]}
          />
        </Field>

        <Field label={t('components.settings.pageSize')}>
          <Select
            value={preferences.pageSize}
            onChange={(e) => updatePreference('pageSize', parseInt(e.target.value))}
            className="max-w-[10rem]"
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </Select>
        </Field>
      </DialogBody>

      <DialogFooter between>
        <Button variant="ghost" size="sm" icon={RotateCcw} onClick={resetPreferences}>
          {t('components.settings.reset')}
        </Button>
        <Button variant="primary" onClick={onClose}>
          {t('components.settings.done')}
        </Button>
      </DialogFooter>
    </Dialog>
  )
}
