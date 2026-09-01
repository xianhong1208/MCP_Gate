import clsx from 'clsx'

/**
 * Table primitives. Usage:
 *   <Table>
 *     <THead><TR><TH>Name</TH><TH align="right">…</TH></TR></THead>
 *     <TBody><TR hover><TD focal>…</TD></TR></TBody>
 *   </Table>
 * The wrapper has a border + overflow-x-auto. Muted header; rows are h-12, border-b separated, hover = 3% foreground.
 */
export default function Table({ className, wrapperClassName, children, bordered = true, ...rest }) {
  return (
    <div className={clsx('w-full overflow-x-auto', bordered && 'rounded-lg border border-border bg-card', wrapperClassName)}>
      <table className={clsx('w-full min-w-full text-sm', className)} {...rest}>
        {children}
      </table>
    </div>
  )
}

export function THead({ className, children }) {
  return <thead className={clsx('border-b border-border bg-muted', className)}>{children}</thead>
}

export function TBody({ className, children }) {
  return <tbody className={clsx('divide-y divide-border', className)}>{children}</tbody>
}

export function TR({ className, hover = true, selected = false, group = true, children, ...rest }) {
  return (
    <tr
      className={clsx(
        group && 'group',
        hover && 'transition-colors duration-200 hover:bg-foreground/[0.03]',
        selected && 'bg-primary-soft/60',
        className,
      )}
      {...rest}
    >
      {children}
    </tr>
  )
}

export function TH({ className, align = 'left', children, ...rest }) {
  return (
    <th
      scope="col"
      className={clsx(
        'relative h-10 whitespace-nowrap px-4 text-xs font-medium uppercase tracking-wide text-muted-foreground',
        align === 'right' && 'text-right',
        align === 'center' && 'text-center',
        align === 'left' && 'text-left',
        className,
      )}
      {...rest}
    >
      {children}
    </th>
  )
}

export function TD({ className, align = 'left', focal = false, mono = false, muted = false, children, ...rest }) {
  return (
    <td
      className={clsx(
        'h-12 px-4 align-middle',
        align === 'right' && 'text-right',
        align === 'center' && 'text-center',
        focal ? 'font-medium text-foreground' : muted ? 'text-muted-foreground' : 'text-foreground',
        mono && 'font-mono text-xs',
        className,
      )}
      {...rest}
    >
      {children}
    </td>
  )
}

/** First column: primary text + secondary line */
export function CellPrimary({ title, subtitle, mono = false, className, titleClassName, children }) {
  return (
    <div className={clsx('min-w-0', className)}>
      <div className={clsx('truncate font-medium text-foreground', mono && 'font-mono text-xs', titleClassName)}>{title ?? children}</div>
      {subtitle && <div className="mt-0.5 truncate text-xs text-muted-foreground">{subtitle}</div>}
    </div>
  )
}

/** Row actions: shown on hover by default, but still keyboard-focusable */
export function RowActions({ className, children, always = false }) {
  return (
    <div
      className={clsx(
        'flex items-center justify-end gap-0.5',
        !always && 'opacity-0 transition-opacity duration-200 group-hover:opacity-100 focus-within:opacity-100',
        className,
      )}
    >
      {children}
    </div>
  )
}
