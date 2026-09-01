import { createContext, useContext, useState, useEffect } from 'react'

const ThemeContext = createContext()

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

export function ThemeProvider({ children }) {
  // Dark is the default and the design baseline; light is used only if the user explicitly chose it.
  // New key (mcp-theme): older builds also wrote the computed default into 'theme', so that key cannot be
  // trusted as a user choice.
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('mcp-theme')
    return saved === 'light' ? 'light' : 'dark'
  })

  // Update document class and localStorage when theme changes
  useEffect(() => {
    const root = document.documentElement

    if (theme === 'light') {
      root.classList.add('light')
      root.classList.remove('dark')
    } else {
      root.classList.add('dark')
      root.classList.remove('light')
    }

  }, [theme])

  // Persist only when the user toggles manually
  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark'
      try { localStorage.setItem('mcp-theme', next) } catch { /* ignore when storage is unavailable */ }
      return next
    })
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}
