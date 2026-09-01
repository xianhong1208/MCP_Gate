import clsx from 'clsx'

/** Keyboard hint */
export function Kbd({ className, children }) {
  return (
    <kbd
      className={clsx(
        'inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded border border-border-strong bg-card px-1 font-mono text-2xs font-medium text-muted-foreground',
        className,
      )}
    >
      {children}
    </kbd>
  )
}

/** Initials avatar: navy square */
export function Avatar({ name, size = 'md', className }) {
  const initial = (name || 'A').trim()[0]?.toUpperCase() || 'A'
  return (
    <span
      className={clsx(
        'inline-flex shrink-0 select-none items-center justify-center rounded-md bg-primary font-medium text-primary-foreground',
        size === 'sm' && 'h-6 w-6 text-xs',
        size === 'md' && 'h-8 w-8 text-sm',
        size === 'lg' && 'h-12 w-12 text-lg',
        className,
      )}
      aria-hidden="true"
    >
      {initial}
    </span>
  )
}

/** Product wordmark: shield mark (green) + name */
export function Wordmark({ name, className, size = 'md' }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <LogoMark className={size === 'lg' ? 'h-7 w-7' : 'h-5 w-5'} />
      <span className={clsx('font-semibold tracking-tight text-foreground', size === 'lg' ? 'text-lg' : 'text-sm')}>{name}</span>
    </span>
  )
}

/** Logo mark: green shield + keyhole in the background color; flat, no gradient */
export function LogoMark({ className }) {
  return (
    <svg viewBox="0 0 20 20" className={clsx('shrink-0 text-accent', className)} aria-hidden="true">
      <path d="M10 1.5 3 4.2v5.3c0 4.3 3 8.1 7 9 4-.9 7-4.7 7-9V4.2L10 1.5Z" fill="currentColor" />
      <circle cx="10" cy="8" r="2.1" className="fill-background" />
      <rect x="9" y="9.2" width="2" height="4.3" rx="1" className="fill-background" />
    </svg>
  )
}

/** Inline code / id */
export function Code({ className, children, ...rest }) {
  return (
    <code className={clsx('rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground', className)} {...rest}>
      {children}
    </code>
  )
}

/** Horizontal divider */
export function Divider({ className }) {
  return <hr className={clsx('border-0 border-t border-border', className)} />
}

/** Divider with text (the login page "or") */
export function DividerWithText({ children, className }) {
  return (
    <div className={clsx('flex items-center gap-3 text-xs text-subtle-foreground', className)}>
      <span className="h-px flex-1 bg-border" />
      {children}
      <span className="h-px flex-1 bg-border" />
    </div>
  )
}
