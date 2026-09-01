/** @type {import('tailwindcss').Config} */

// Design system "Navy Trust" -- Minimalism & Swiss Style, dark-first
// ---------------------------------------------------------------------------
// Every color is a semantic token whose value is a CSS variable defined in src/index.css:
//   one set for `html.dark` (default), one for `html.light`.
// Pages only use bg-card / text-muted-foreground / border-border etc.; they follow the theme without dark: everywhere.
//
//   background / foreground        page background + primary text
//   card / popover / muted         cards, overlays, sidebar and table header backgrounds
//   muted-foreground / subtle-foreground   two levels of secondary text
//   border / border-strong         dividers / control borders (strings with alpha; /alpha not supported)
//   primary                        navy: selected state, sidebar active, secondary solid buttons, light-mode links
//   accent                         green CTA (only one solid green per screen)
//   link                           text links (green in dark, navy in light)
//   destructive                    solid delete button (#DC2626 + white text)
//   success / warning / danger / info   semantic colors (text, dots, tinted backgrounds)
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  // class strategy: ThemeContext toggles html.dark / html.light
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: token('color-background'),
        foreground: token('color-foreground'),
        card: {
          DEFAULT: token('color-card'),
          foreground: token('color-card-foreground'),
        },
        popover: token('color-popover'),
        muted: {
          DEFAULT: token('color-muted'),
          foreground: token('color-muted-foreground'),
        },
        subtle: {
          foreground: token('color-subtle-foreground'),
        },
        border: {
          DEFAULT: 'var(--color-border)',
          strong: 'var(--color-border-strong)',
        },
        primary: {
          DEFAULT: token('color-primary'),
          hover: token('color-primary-hover'),
          foreground: token('color-primary-foreground'),
          soft: token('color-primary-soft'),
          'soft-foreground': token('color-primary-soft-foreground'),
        },
        accent: {
          DEFAULT: token('color-accent'),
          hover: token('color-accent-hover'),
          foreground: token('color-accent-foreground'),
        },
        link: {
          DEFAULT: token('color-link'),
          hover: token('color-link-hover'),
        },
        destructive: {
          DEFAULT: token('color-destructive'),
          hover: token('color-destructive-hover'),
          foreground: token('color-destructive-foreground'),
        },
        ring: token('color-ring'),
        success: token('color-success'),
        warning: token('color-warning'),
        danger: token('color-danger'),
        info: token('color-info'),
      },
      fontFamily: {
        sans: ['"Fira Sans"', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      borderRadius: {
        // Swiss: small radii. md = controls (6px), lg = cards (8px)
        DEFAULT: '0.25rem',
        md: '0.375rem',
        lg: '0.5rem',
        xl: '0.5rem',
      },
      boxShadow: {
        // Cards cast no shadow; only overlays (dialog / popover / toast) get one small, sharp shadow
        overlay: '0 1px 2px rgb(0 0 0 / 0.3), 0 8px 24px -8px rgb(0 0 0 / 0.4)',
      },
      transitionDuration: {
        DEFAULT: '200ms',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'dialog-in': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'toast-in': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'fade-in': 'fade-in 200ms ease-out both',
        'dialog-in': 'dialog-in 200ms ease-out both',
        'toast-in': 'toast-in 200ms ease-out both',
      },
    },
  },
  plugins: [],
}
