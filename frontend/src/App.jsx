import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './contexts/AuthContext'
import { rememberRedirect } from './utils/redirect'
import Layout from './components/Layout'
import Spinner from './components/ui/Spinner'
import LoginPage from './pages/LoginPage'
import SetupPage from './pages/SetupPage'
import ConsentPage from './pages/ConsentPage'
import DashboardPage from './pages/DashboardPage'
import TokensPage from './pages/TokensPage'
import TokenDetailPage from './pages/TokenDetailPage'
import CreateTokenPage from './pages/CreateTokenPage'
import ServicesPage from './pages/ServicesPage'
import ServiceDetailPage from './pages/ServiceDetailPage'
import OAuthClientsPage from './pages/OAuthClientsPage'
import MarketplacePage from './pages/MarketplacePage'
import AuditLogPage from './pages/AuditLogPage'

function FullScreenSpinner() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-subtle-foreground">
      <Spinner size="lg" />
    </div>
  )
}

/**
 * Not logged in -> remember the current location, then go to /login.
 * This is critical for the OAuth flow: the backend sends an unauthenticated browser to /consent?rid=...,
 * and after login (including GitHub / Google) we must return to that same consent page to resume the request.
 */
function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) return <FullScreenSpinner />

  if (!isAuthenticated) {
    rememberRedirect(location.pathname + location.search)
    return <Navigate to="/login" replace />
  }

  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/setup" element={<SetupPage />} />
      <Route
        path="/consent"
        element={
          <ProtectedRoute>
            <ConsentPage />
          </ProtectedRoute>
        }
      />

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="services" element={<ServicesPage />} />
        <Route path="services/:serviceId" element={<ServiceDetailPage />} />
        <Route path="tokens" element={<TokensPage />} />
        <Route path="tokens/create" element={<CreateTokenPage />} />
        <Route path="tokens/:jti" element={<TokenDetailPage />} />
        <Route path="clients" element={<OAuthClientsPage />} />
        <Route path="marketplace" element={<MarketplacePage />} />
        <Route path="audit" element={<AuditLogPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
