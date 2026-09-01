import { forwardRef } from 'react'
import clsx from 'clsx'

/** Form label: text-sm medium, placed above the field */
export function Label({ className, children, required, ...rest }) {
  return (
    <label className={clsx('mb-1.5 block text-sm font-medium text-foreground', className)} {...rest}>
      {children}
      {required && <span className="ml-0.5 text-danger" aria-hidden="true">*</span>}
    </label>
  )
}

/** Help text below the field */
export function Help({ className, children }) {
  if (!children) return null
  return <p className={clsx('mt-1.5 text-xs text-muted-foreground', className)}>{children}</p>
}

/** Field error */
export function FieldError({ className, children }) {
  if (!children) return null
  return <p className={clsx('mt-1.5 text-xs text-danger', className)}>{children}</p>
}

/** Field = layout container for Label + control + Help/Error */
export function Field({ label, htmlFor, help, error, required, className, children }) {
  return (
    <div className={clsx('min-w-0', className)}>
      {label && <Label htmlFor={htmlFor} required={required}>{label}</Label>}
      {children}
      {error ? <FieldError>{error}</FieldError> : <Help>{help}</Help>}
    </div>
  )
}

export const Input = forwardRef(function Input({ className, size = 'md', invalid = false, mono = false, ...rest }, ref) {
  return (
    <input
      ref={ref}
      className={clsx('ui-input', size === 'sm' && 'ui-input-sm', invalid && 'ui-input-error', mono && 'font-mono', className)}
      {...rest}
    />
  )
})

export const Select = forwardRef(function Select({ className, size = 'md', invalid = false, children, ...rest }, ref) {
  return (
    <select
      ref={ref}
      className={clsx('ui-input', size === 'sm' && 'ui-input-sm', invalid && 'ui-input-error', className)}
      {...rest}
    >
      {children}
    </select>
  )
})

export const Textarea = forwardRef(function Textarea({ className, invalid = false, mono = false, ...rest }, ref) {
  return (
    <textarea
      ref={ref}
      className={clsx('ui-input resize-none', invalid && 'ui-input-error', mono && 'font-mono', className)}
      {...rest}
    />
  )
})

export const Checkbox = forwardRef(function Checkbox({ className, ...rest }, ref) {
  return <input ref={ref} type="checkbox" className={clsx('ui-checkbox', className)} {...rest} />
})

export const Radio = forwardRef(function Radio({ className, ...rest }, ref) {
  return <input ref={ref} type="radio" className={clsx('ui-radio', className)} {...rest} />
})

/** Checkbox row with description (consent scopes, boolean form options) */
export function CheckRow({ label, description, className, disabled, ...inputProps }) {
  return (
    <label
      className={clsx(
        'flex items-start gap-3 text-sm',
        disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
        className,
      )}
    >
      <Checkbox className="mt-0.5" disabled={disabled} {...inputProps} />
      <span className="min-w-0">
        <span className="block font-medium text-foreground">{label}</span>
        {description && <span className="mt-0.5 block text-xs text-muted-foreground">{description}</span>}
      </span>
    </label>
  )
}

/** Search box: Input with a leading icon */
export function SearchInput({ className, icon: Icon, size = 'md', ...rest }) {
  return (
    <div className={clsx('relative', className)}>
      {Icon && <Icon className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-subtle-foreground" aria-hidden="true" />}
      <Input type="search" size={size} className={clsx(Icon && 'pl-8')} {...rest} />
    </div>
  )
}
