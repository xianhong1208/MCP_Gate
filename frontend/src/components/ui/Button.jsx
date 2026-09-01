import { forwardRef } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import Spinner from './Spinner'

/**
 * Button -- the single source of button styles for the whole app.
 *
 * variant:
 *   primary      solid green CTA (dark text; at most one per screen)
 *   secondary    card background + border (outline)
 *   ghost        no border, background only on hover
 *   destructive  danger text, tinted danger background on hover (use destructiveSolid only inside confirm dialogs)
 *   destructiveSolid  solid #DC2626 + white text
 *   soft         solid navy (for selected / toggled state; do not fake it by overriding secondary via className)
 * size: md(h-9)| sm(h-8)| xs(h-7)
 * Pass `to` to render a <Link>, `href` to render an <a>.
 */
export const buttonVariants = {
  primary:
    'bg-accent text-accent-foreground hover:bg-accent-hover border border-transparent',
  secondary:
    'bg-card text-foreground border border-border-strong hover:bg-foreground/[0.06]',
  ghost:
    'bg-transparent text-muted-foreground border border-transparent hover:bg-foreground/[0.06] hover:text-foreground',
  destructive:
    'bg-transparent text-danger border border-transparent hover:bg-danger/10',
  destructiveSolid:
    'bg-destructive text-destructive-foreground hover:bg-destructive-hover border border-transparent',
  soft:
    'bg-primary text-primary-foreground border border-transparent hover:bg-primary-hover',
}

export const buttonSizes = {
  md: 'h-9 px-3.5 text-sm gap-2',
  sm: 'h-8 px-3 text-sm gap-1.5',
  xs: 'h-7 px-2.5 text-xs gap-1.5',
}

const Button = forwardRef(function Button(
  { variant = 'secondary', size = 'md', loading = false, icon: Icon, className, children, to, href, disabled, type, ...rest },
  ref,
) {
  const classes = clsx(
    'inline-flex cursor-pointer items-center justify-center whitespace-nowrap rounded-md font-medium',
    'transition-colors duration-200 select-none',
    'disabled:pointer-events-none disabled:opacity-50',
    buttonVariants[variant] || buttonVariants.secondary,
    buttonSizes[size] || buttonSizes.md,
    className,
  )
  const content = (
    <>
      {loading ? <Spinner size="xs" className="shrink-0" /> : Icon ? <Icon className="h-4 w-4 shrink-0" aria-hidden="true" /> : null}
      {children}
    </>
  )
  if (to) {
    return (
      <Link ref={ref} to={to} className={clsx(classes, disabled && 'pointer-events-none opacity-50')} {...rest}>
        {content}
      </Link>
    )
  }
  if (href) {
    return (
      <a ref={ref} href={href} className={classes} {...rest}>
        {content}
      </a>
    )
  }
  return (
    <button ref={ref} type={type || 'button'} className={classes} disabled={disabled || loading} {...rest}>
      {content}
    </button>
  )
})

export default Button
