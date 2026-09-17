import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

// Flat config (ESLint 9). Lints the console source, its node-based tests and build scripts.
// The built bundle in ../static is generated and never linted.
export default [
  { ignores: ['dist', 'node_modules', '../static'] },
  {
    files: ['**/*.{js,jsx,mjs}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: { react, 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    settings: { react: { version: 'detect' } },
    rules: {
      ...js.configs.recommended.rules,
      // Mark components referenced in JSX as used (the automatic runtime needs no React import).
      'react/jsx-uses-vars': 'error',
      ...reactHooks.configs.recommended.rules,
      // Pages export helper components (KindBadge, ScopeChips) next to the default page; Fast Refresh
      // then reloads the whole module instead of patching, which is acceptable for an admin console.
      'react-refresh/only-export-components': 'off',
      // Unused imports are bugs; unused function args prefixed "_" are deliberate.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      // `try { ... } catch {}` is the best-effort cleanup idiom here (logout, socket close).
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
]
