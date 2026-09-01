import { Link } from 'react-router-dom'
import clsx from 'clsx'

/**
 * Card -- card background + border, no shadow (Swiss: flat, separated by lines).
 * padding: 'md'(p-5)| 'sm'(p-4)| 'none'
 * Pass `to` to make it a clickable Link card (border darkens on hover).
 */
export default function Card({ as, to, padding = 'md', interactive = false, className, children, ...rest }) {
  const Comp = to ? Link : as || 'div'
  return (
    <Comp
      to={to}
      className={clsx(
        'rounded-lg border border-border bg-card text-card-foreground',
        padding === 'md' && 'p-5',
        padding === 'sm' && 'p-4',
        (interactive || to) && 'cursor-pointer transition-colors duration-200 hover:border-border-strong hover:bg-foreground/[0.03]',
        className,
      )}
      {...rest}
    >
      {children}
    </Comp>
  )
}

/** Card header: title (text-sm semibold) + description + actions on the right */
export function CardHeader({ title, description, action, className, divided = false }) {
  return (
    <div
      className={clsx(
        'flex items-start justify-between gap-4',
        divided ? '-mx-5 -mt-5 mb-5 border-b border-border px-5 py-4' : 'mb-4',
        className,
      )}
    >
      <div className="min-w-0">
        {title && <h3 className="text-sm font-semibold text-foreground">{title}</h3>}
        {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
      </div>
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  )
}

/** Section label: xs uppercase tracking-wide muted (the only place uppercase is allowed) */
export function SectionLabel({ className, children, ...rest }) {
  return (
    <p className={clsx('text-xs font-medium uppercase tracking-wide text-muted-foreground', className)} {...rest}>
      {children}
    </p>
  )
}

/** Stat tile: label / value / meta */
export function StatTile({ label, value, meta, to, loading = false, className }) {
  return (
    <Card to={to} className={clsx('min-w-0', className)}>
      <SectionLabel>{label}</SectionLabel>
      {loading ? (
        <div className="skeleton mt-2 h-8 w-16" />
      ) : (
        <p className="mt-2 text-2xl font-semibold tabular-nums tracking-tight text-foreground">{value}</p>
      )}
      {meta && !loading && <p className="mt-1 truncate text-xs text-muted-foreground">{meta}</p>}
    </Card>
  )
}

/** Key-value list (for detail pages): dt on the left, dd on the right */
export function DescriptionList({ items, className }) {
  return (
    <dl className={clsx('divide-y divide-border', className)}>
      {items.filter(Boolean).map(({ label, value, mono }) => (
        <div key={label} className="flex items-start justify-between gap-6 py-2.5 text-sm">
          <dt className="shrink-0 text-muted-foreground">{label}</dt>
          <dd className={clsx('min-w-0 text-right text-foreground break-all', mono && 'font-mono text-xs')}>{value}</dd>
        </div>
      ))}
    </dl>
  )
}
