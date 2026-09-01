import { useTranslation } from 'react-i18next'
import clsx from 'clsx'
import ThemeToggle from './ThemeToggle'
import LanguageSwitcher from './LanguageSwitcher'
import { Wordmark } from './ui'

/**
 * Full-screen centered card layout (shared by login / first-run setup / OAuth consent):
 * background fill, wordmark on top, card + border, language / theme switchers in the top-right corner.
 */
export default function AuthShell({ children, maxWidth = 'max-w-sm', showLogo = true }) {
  const { t } = useTranslation()

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-12">
      <div className="absolute right-4 top-4 flex items-center gap-1">
        <LanguageSwitcher />
        <ThemeToggle />
      </div>

      <div className={clsx('w-full', maxWidth)}>
        {showLogo && (
          <div className="mb-6 flex justify-center">
            <Wordmark name={t('auth.appName')} size="lg" />
          </div>
        )}

        <div className="rounded-lg border border-border bg-card p-6">
          {children}
        </div>

        <p className="mt-6 text-center text-xs text-subtle-foreground">
          {t('auth.tagline')}
        </p>
      </div>
    </div>
  )
}
