import { useState, useEffect } from 'react'
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import GlobalSearch from './GlobalSearch'
import { useAuth } from '../contexts/AuthContext'
import { systemApi } from '../services/api'
import ThemeToggle from './ThemeToggle'
import LanguageSwitcher from './LanguageSwitcher'
import SettingsModal from './SettingsModal'
import ProfileModal from './ProfileModal'
import {
  LayoutDashboard,
  Key,
  Plus,
  Server,
  Store,
  LogOut,
  Bot,
  FileText,
  Settings,
  Menu,
  X,
} from 'lucide-react'
import clsx from 'clsx'
import { IconButton, Avatar, Wordmark } from './ui'

/**
 * App shell (standard admin layout, as in GitHub / Vercel / Supabase):
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │ [≡] 🛡 MCP Center   [🔍 search]            ⚙ ☀ A │ 👤 name  ⎋ │  top bar 56px, full width
 *   ├────────────┬─────────────────────────────────────────────────┤
 *   │ nav        │ page title                     [primary action] │
 *   │ …          │ content                                         │
 *   │ version    │                                                 │
 *   └────────────┴─────────────────────────────────────────────────┘
 *
 * - Top bar: brand + search + account actions (settings / theme / language / profile / logout)
 * - Sidebar: navigation only (256px), starts below the top bar
 * - Content: starts below the top bar; title and content share the same left edge
 */

// Single tenant: any logged-in user is the admin, so the menu is not permission-filtered
const navItems = [
  { to: '/', icon: LayoutDashboard, labelKey: 'nav.dashboard', end: true },
  { to: '/services', icon: Server, labelKey: 'nav.services' },
  { to: '/tokens', end: true, icon: Key, labelKey: 'nav.tokens' },
  { to: '/tokens/create', icon: Plus, labelKey: 'nav.issueToken' },
  { to: '/clients', icon: Bot, labelKey: 'nav.clients' },
  { to: '/marketplace', icon: Store, labelKey: 'nav.marketplace' },
  { to: '/audit', icon: FileText, labelKey: 'nav.audit' },
]

const SIDEBAR_WIDTH = 'w-64'          // 256px
const SIDEBAR_OFFSET = 'lg:pl-64'
const TOPBAR_HEIGHT = 'h-14'          // 56px
const TOPBAR_OFFSET = 'top-14'

export default function Layout() {
  const { t } = useTranslation()
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [showSettings, setShowSettings] = useState(false)
  const [showProfile, setShowProfile] = useState(false)
  const [version, setVersion] = useState(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    systemApi.getVersion().then(setVersion).catch(() => {})
  }, [])

  // Auto-close drawer when navigating on narrow screens
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const displayName = user?.username || user?.email || t('layout.adminFallback')

  return (
    <div className="min-h-screen">
      {/* ── Top bar ────────────────────────────────────────────────────── */}
      <header
        className={clsx(
          'fixed inset-x-0 top-0 z-50 flex items-center gap-2 border-b border-border bg-muted px-3 sm:px-4',
          TOPBAR_HEIGHT,
        )}
      >
        {/* Left: menu (mobile) + brand; same width as the sidebar so the brand sits right above it */}
        <div className="flex shrink-0 items-center gap-1 lg:w-[calc(theme(spacing.64)-theme(spacing.4))]">
          <IconButton
            icon={sidebarOpen ? X : Menu}
            title={sidebarOpen ? t('layout.closeMenu') : t('layout.openMenu')}
            onClick={() => setSidebarOpen((open) => !open)}
            className="lg:hidden"
          />
          <Wordmark name={t('layout.appName')} />
        </div>

        {/* Middle: global search (right after the brand, aligned with the content's left edge) */}
        <GlobalSearch className="hidden w-80 md:flex" />

        <div className="flex-1" />

        {/* Right: account actions */}
        <div className="flex items-center gap-0.5">
          <IconButton icon={Settings} title={t('layout.settings')} onClick={() => setShowSettings(true)} />
          <ThemeToggle />
          <LanguageSwitcher />
          <span className="mx-1.5 h-5 w-px bg-border" aria-hidden="true" />
          <button
            onClick={() => setShowProfile(true)}
            className="flex h-9 cursor-pointer items-center gap-2 rounded-md px-1.5 text-left transition-colors duration-200 hover:bg-foreground/[0.06]"
            title={t('layout.profile')}
          >
            <Avatar name={displayName} />
            <span className="hidden min-w-0 sm:block">
              <span className="block max-w-[10rem] truncate text-sm font-medium leading-4 text-foreground">{displayName}</span>
              <span className="block max-w-[10rem] truncate text-2xs leading-4 text-muted-foreground">{user?.email || ''}</span>
            </span>
          </button>
          <IconButton icon={LogOut} title={t('layout.logout')} onClick={handleLogout} />
        </div>
      </header>

      {/* Mobile drawer backdrop */}
      {sidebarOpen && (
        <div
          className={clsx('fixed inset-x-0 bottom-0 z-30 bg-black/60 lg:hidden', TOPBAR_OFFSET)}
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* ── Sidebar (navigation only, starts below the top bar) ───────── */}
      <aside
        className={clsx(
          'fixed bottom-0 left-0 z-40 flex flex-col border-r border-border bg-muted',
          SIDEBAR_WIDTH, TOPBAR_OFFSET,
          'transition-transform duration-200 ease-out lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                clsx(
                  'relative flex h-8 items-center gap-2.5 rounded-md px-2.5 text-sm transition-colors duration-200',
                  isActive
                    ? 'bg-primary font-medium text-primary-foreground before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-r before:bg-accent before:content-[""]'
                    : 'text-muted-foreground hover:bg-foreground/[0.06] hover:text-foreground',
                )
              }
            >
              <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="truncate">{t(item.labelKey)}</span>
            </NavLink>
          ))}
        </nav>
        {version && (
          <div className="border-t border-border px-5 py-3">
            <p className="text-2xs text-muted-foreground">{t('layout.version', { version: version.version })}</p>
          </div>
        )}
      </aside>

      {/* ── Content ────────────────────────────────────────────────────── */}
      <main className={clsx('min-w-0 pt-14', SIDEBAR_OFFSET)}>
        <div className="mx-auto w-full max-w-7xl px-6 py-8">
          <Outlet />
        </div>
      </main>

      <SettingsModal isOpen={showSettings} onClose={() => setShowSettings(false)} />
      <ProfileModal isOpen={showProfile} onClose={() => setShowProfile(false)} />
    </div>
  )
}
