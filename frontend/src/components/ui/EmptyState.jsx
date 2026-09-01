import clsx from 'clsx'

/** Empty state: square icon box + one-line title + optional description + optional action */
export default function EmptyState({ icon: Icon, title, description, action, className, compact = false }) {
  return (
    <div className={clsx('flex flex-col items-center justify-center text-center', compact ? 'py-8' : 'py-14', className)}>
      {Icon && (
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-md border border-border bg-muted text-subtle-foreground">
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
      )}
      {title && <p className="text-sm font-medium text-foreground">{title}</p>}
      {description && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{description}</p>}
      {action && <div className="mt-4 flex items-center gap-2">{action}</div>}
    </div>
  )
}
