import { createContext, useContext, useState, useEffect, useCallback } from 'react'

const PreferencesContext = createContext()

const DEFAULT_PREFERENCES = {
  // Table preferences
  pageSize: 20,
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
        return { ...DEFAULT_PREFERENCES, ...JSON.parse(saved) }
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
