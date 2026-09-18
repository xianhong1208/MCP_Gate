import { createContext, useContext, useState, useEffect, useCallback } from 'react'

const PreferencesContext = createContext()

// Bump when a default changes so browsers that only ever stored the old default pick up the new one;
// a value the user chose in Settings after that is kept as-is.
const PREFERENCES_VERSION = 2

const DEFAULT_PREFERENCES = {
  prefsVersion: PREFERENCES_VERSION,
  // Table preferences
  pageSize: 10,
  defaultSort: 'created_at',
  sortDirection: 'desc',

  // Sidebar
  sidebarCollapsed: false,
}

export function usePreferences() {
  const context = useContext(PreferencesContext)
  if (!context) {
    throw new Error('usePreferences must be used within a PreferencesProvider')
  }
  return context
}

export function PreferencesProvider({ children }) {
  const [preferences, setPreferences] = useState(() => {
    try {
      const saved = localStorage.getItem('userPreferences')
      if (saved) {
        const parsed = JSON.parse(saved)
        if (parsed.prefsVersion !== PREFERENCES_VERSION) {
          delete parsed.pageSize   // v1 persisted the old default (20) for everyone; let the new default apply
        }
        return { ...DEFAULT_PREFERENCES, ...parsed, prefsVersion: PREFERENCES_VERSION }
      }
    } catch (e) {
      console.error('Failed to load preferences:', e)
    }
    return DEFAULT_PREFERENCES
  })

  // Save to localStorage when preferences change
  useEffect(() => {
    try {
      localStorage.setItem('userPreferences', JSON.stringify(preferences))
    } catch (e) {
      console.error('Failed to save preferences:', e)
    }
  }, [preferences])

  const updatePreference = useCallback((key, value) => {
    setPreferences(prev => ({ ...prev, [key]: value }))
  }, [])

  const updatePreferences = useCallback((updates) => {
    setPreferences(prev => ({ ...prev, ...updates }))
  }, [])

  const resetPreferences = useCallback(() => {
    setPreferences(DEFAULT_PREFERENCES)
  }, [])

  return (
    <PreferencesContext.Provider
      value={{
        preferences,
        updatePreference,
        updatePreferences,
        resetPreferences,
      }}
    >
      {children}
    </PreferencesContext.Provider>
  )
}
