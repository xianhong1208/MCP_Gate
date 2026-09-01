import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Copy, Check } from 'lucide-react'
import clsx from 'clsx'
import { copyToClipboard } from '../utils/clipboard'
import { useToast } from '../contexts/ToastContext'
import IconButton from './ui/IconButton'
import Button from './ui/Button'

/**
 * Copyable code / command block.
 * `value` may be a string or an object (objects are JSON.stringify'd with 2-space indent).
 * `copyLabel` renders a labelled primary button instead of the icon button — use it when copying is the page's main action.
 */
export default function CodeBlock({ title, value, language, className, rows, sensitive = false, copyLabel }) {
  const { t } = useTranslation()
  const toast = useToast()
  const [copied, setCopied] = useState(false)
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2)

  const handleCopy = async () => {
    try {
      await copyToClipboard(text)
      setCopied(true)
      toast.success(t('components.code.copied'))
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error(t('components.code.copyFailed'))
    }
  }

  const copyButton = copyLabel ? (
    <Button variant="primary" size="sm" icon={copied ? Check : Copy} onClick={handleCopy}>{copyLabel}</Button>
  ) : (
    <IconButton
      size="sm"
      icon={copied ? Check : Copy}
      onClick={handleCopy}
      title={t('components.code.copy')}
      className={clsx(copied && 'text-success')}
    />
  )

  return (
    <div className={clsx('overflow-hidden rounded-md border border-border bg-muted/50', className)}>
      {(title || language) && (
        <div className="flex h-9 items-center justify-between border-b border-border px-3">
          <span className="truncate text-xs font-medium text-muted-foreground">{title}</span>
          <div className="flex items-center gap-2">
            {language && <span className="font-mono text-2xs uppercase tracking-wide text-subtle-foreground">{language}</span>}
            {copyButton}
          </div>
        </div>
      )}
      <div className="relative">
        <pre
          className={clsx(
            'overflow-x-auto whitespace-pre px-3 py-2.5 font-mono text-xs leading-relaxed text-foreground',
            sensitive && 'whitespace-pre-wrap break-all',
          )}
          style={rows ? { maxHeight: `${rows * 1.6}rem`, overflowY: 'auto' } : undefined}
        >
          {text}
        </pre>
        {!title && !language && (
          <div className="absolute right-1.5 top-1.5">{copyButton}</div>
        )}
      </div>
    </div>
  )
}
