import clsx from 'clsx'

/**
 * Tabs (controlled): items = [{ key, label, count?, icon? }]
 * Underline style; the selected tab uses a foreground underline + foreground text (Swiss: high contrast, not color).
 */
export default function Tabs({ items, value, onChange, className, size = 'md' }) {
  return (
    <div className={clsx('flex items-center gap-1 border-b border-border', className)} role="tablist">
      {items.map((item) => {
        const active = item.key === value
        const Icon = item.icon
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.key)}
            className={clsx(
              '-mb-px inline-flex shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap border-b-2 px-3 font-medium transition-colors duration-200',
              size === 'md' ? 'h-10 text-sm' : 'h-9 text-sm',
              active
                ? 'border-foreground text-foreground'
                : 'border-transparent text-muted-foreground hover:border-border-strong hover:text-foreground',
            )}
          >
            {Icon && <Icon className="h-4 w-4" aria-hidden="true" />}
            {item.label}
            {item.count != null && (
              <span
                className={clsx(
                  'ml-0.5 inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded px-1.5 text-xs tabular-nums',
                  active ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground',
                )}
              >
                {item.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

/** Segmented control (small): items = [{ key, label }]; selected = solid navy */
export function SegmentedControl({ items, value, onChange, className, size = 'md' }) {
  return (
    <div className={clsx('inline-flex items-center rounded-md border border-border-strong bg-muted p-0.5', className)} role="tablist">
      {items.map((item) => {
        const active = item.key === value
        const Icon = item.icon
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.key)}
            className={clsx(
              'inline-flex shrink-0 cursor-pointer items-center gap-1.5 whitespace-nowrap rounded px-2.5 font-medium transition-colors duration-200',
              size === 'md' ? 'h-7 text-sm' : 'h-6 text-xs',
              active ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {Icon && <Icon className="h-3.5 w-3.5" aria-hidden="true" />}
            {item.label}
          </button>
        )
      })}
    </div>
  )
}
