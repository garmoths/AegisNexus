import * as React from 'react'
import { cva } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const alertVariants = cva(
  'relative w-full rounded-lg border px-4 py-3 text-sm flex items-start gap-3 [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:mt-0.5',
  {
    variants: {
      variant: {
        default: 'border-border bg-card text-card-foreground',
        destructive: 'border-destructive/40 bg-destructive/10 text-destructive',
        success: 'border-[color:var(--success)]/40 bg-[color:var(--success)]/10 text-[color:var(--success)]',
        warning: 'border-[color:var(--warning)]/40 bg-[color:var(--warning)]/10 text-[color:var(--warning)]',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

const Alert = React.forwardRef(function Alert({ className, variant, ...props }, ref) {
  return <div ref={ref} role="alert" className={cn(alertVariants({ variant }), className)} {...props} />
})

const AlertTitle = React.forwardRef(function AlertTitle({ className, ...props }, ref) {
  return <h5 ref={ref} className={cn('mb-0.5 font-semibold leading-none tracking-tight', className)} {...props} />
})

const AlertDescription = React.forwardRef(function AlertDescription({ className, ...props }, ref) {
  return <div ref={ref} className={cn('text-sm [&_p]:leading-relaxed opacity-90', className)} {...props} />
})

export { Alert, AlertTitle, AlertDescription }
