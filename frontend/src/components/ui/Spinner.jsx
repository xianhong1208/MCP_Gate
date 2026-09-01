import clsx from 'clsx'

const sizes = {
  xs: 'h-3.5 w-3.5 border-[1.5px]',
  sm: 'h-4 w-4 border-2',
  md: 'h-5 w-5 border-2',
  lg: 'h-6 w-6 border-2',
}

/** Circular spinner: uses currentColor, so it works inside any text color */
export default function Spinner({ size = 'md', className }) {
  return (
    <span
      role="status"
      aria-live="polite"
      className={clsx(
        'inline-block shrink-0 animate-spin rounded-full border-current border-t-transparent',
        sizes[size] || sizes.md,
        className,
      )}
    />
  )
}

/** Block loading state (page / card content) */
export function LoadingBlock({ className, size = 'md' }) {
  return (
    <div className={clsx('flex items-center justify-center py-12 text-subtle-foreground', className)}>
      <Spinner size={size} />
    </div>
  )
}
