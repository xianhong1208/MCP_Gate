import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import clsx from 'clsx'
import GlobalSearch from '../GlobalSearch'

/**
 * Top of every page: title (text-xl semibold) + one-line description + actions on the right (at most one primary).
 * backTo / backLabel: show a link to the parent page (detail pages).
 * meta: small element next to the title (StatusPill / Badge).
 * search: whether to place the global search box left of the title (off by default; global search lives in Layout).
 */
export default function PageHeader({ title, description, actions, backTo, backLabel, meta, className, search = false }) {
  return (
    <div className={clsx('flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between', className)}>
      <div className="flex min-w-0 items-start gap-6">
      {search && <GlobalSearch className="hidden w-72 shrink-0 lg:flex" />}
      <div className="min-w-0">
        {backTo && (
          <Link
            to={backTo}
            className="mb-2 inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors duration-200 hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
            {backLabel}
          </Link>
        )}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <h1 className="truncate text-xl font-semibold tracking-tight text-foreground">{title}</h1>
          {meta}
        </div>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** Page container: max-w-7xl, space-y-8 between sections */
export function Page({ className, children, narrow = false }) {
  return (
    <div className={clsx('mx-auto w-full space-y-8', narrow ? 'max-w-3xl' : 'max-w-7xl', className)}>
      {children}
    </div>
  )
}
