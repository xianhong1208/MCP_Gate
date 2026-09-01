import clsx from 'clsx'

/**
 * Every semantic tone is "tinted bg /10 + tone text + inset ring /20"; both themes share the same classes
 * (tokens swap values).
 * tone: neutral | accent (navy, for kind / tags) | success | warning | danger | info
 */
export const badgeTones = {
  neutral: 'bg-muted text-muted-foreground ring-border',
  accent: 'bg-primary-soft text-primary-soft-foreground ring-primary/40',
  success: 'bg-success/10 text-success ring-success/20',
  warning: 'bg-warning/10 text-warning ring-warning/20',
  danger: 'bg-danger/10 text-danger ring-danger/20',
  info: 'bg-info/10 text-info ring-info/20',
}

export const dotTones = {
  neutral: 'bg-subtle-foreground',
  accent: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  info: 'bg-info',
}

/** Small label (kind / tag / scope) */
export default function Badge({ tone = 'neutral', mono = false, size = 'sm', className, children, ...rest }) {
  return (
    <span
      className={clsx(
        'inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded font-medium ring-1 ring-inset',
        size === 'sm' ? 'h-5 px-1.5 text-xs' : 'h-6 px-2 text-xs',
        mono && 'font-mono',
        badgeTones[tone] || badgeTones.neutral,
        className,
      )}
      {...rest}
    >
      {children}
    </span>
  )
}

/** Status: dot + text. Use `pulse` for in-progress states. */
export function StatusPill({ tone = 'neutral', pulse = false, className, children, ...rest }) {
  return (
    <span
      className={clsx('inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-xs font-medium text-muted-foreground', className)}
      {...rest}
    >
      <span
        className={clsx('h-1.5 w-1.5 shrink-0 rounded-full', dotTones[tone] || dotTones.neutral, pulse && 'animate-pulse')}
        aria-hidden="true"
      />
      {children}
    </span>
  )
}

/** Plain colored dot (for the first table column) */
export function StatusDot({ tone = 'neutral', pulse = false, className }) {
  return (
    <span
      className={clsx('inline-block h-2 w-2 shrink-0 rounded-full', dotTones[tone] || dotTones.neutral, pulse && 'animate-pulse', className)}
      aria-hidden="true"
    />
  )
}
