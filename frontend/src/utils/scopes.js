/**
 * Scope descriptions live in the database (editable in the console) and are English by default.
 * When the active locale ships a translation for a well-known scope, prefer it; otherwise fall back
 * to the stored description. Keys use '_' instead of ':' because ':' is i18next's namespace separator.
 */
export function describeScope(t, name, stored) {
  const key = `scopes.desc.${String(name || '').replace(/:/g, '_')}`
  const translated = t(key)
  return translated === key ? (stored || '') : translated
}
