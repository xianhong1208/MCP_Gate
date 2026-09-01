import { forwardRef } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'

/**
 * IconButton -- square 8x8 (h-8 w-8) icon button; `title` is required (it doubles as aria-label).
 * variant: ghost | secondary | destructive | accent
 * size: md(h-8)| sm(h-7)
 */
const variants = {
  ghost: 'text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground border border-transparent',
  secondary: 'text-muted-foreground bg-card border border-border-strong hover:bg-foreground/[0.06] hover:text-foreground',
  destructive: 'text-muted-foreground hover:bg-danger/10 hover:text-danger border border-transparent',
  accent: 'text-muted-foreground hover:bg-accent/10 hover:text-accent border border-transparent',
}

const sizes = {
  md: 'h-8 w-8',
  sm: 'h-7 w-7',
}

const IconButton = forwardRef(function IconButton(
  { icon: Icon, title, variant = 'ghost', size = 'md', className, to, children, type, ...rest },
  ref,
) {
  const classes = clsx(
    'inline-flex shrink-0 cursor-pointer items-center justify-center rounded-md transition-colors duration-200',
    'disabled:pointer-events-none disabled:opacity-40',
    variants[variant] || variants.ghost,
    sizes[size] || sizes.md,
    className,
  )
  const content = Icon ? <Icon className="h-4 w-4" aria-hidden="true" /> : children
  if (to) {
    return (
      <Link ref={ref} to={to} title={title} aria-label={title} className={classes} {...rest}>
        {content}
      </Link>
    )
  }
  return (
    <button ref={ref} type={type || 'button'} title={title} aria-label={title} className={classes} {...rest}>
      {content}
    </button>
  )
})

export default IconButton
