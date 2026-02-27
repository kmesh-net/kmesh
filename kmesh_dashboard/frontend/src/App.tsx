import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import RequireAuth from './components/auth/RequireAuth'
import ClusterNodesPage from './pages/cluster/ClusterNodesPage'
import TopologyPage from './pages/topology/TopologyPage'
import WaypointPage from './pages/waypoint'
import CircuitBreakerPage from './pages/circuitbreaker'
import RateLimitPage from './pages/ratelimit'
import MetricsPage from './pages/metrics/MetricsPage'
import HelpPage from './pages/help/HelpPage'
import LoginPage from './pages/auth/LoginPage'
import { AuthProvider } from './contexts/AuthContext'

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Navigate to="/cluster/nodes" replace />} />
            <Route path="cluster/nodes" element={<ClusterNodesPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="waypoint" element={<WaypointPage />} />
            <Route path="circuitbreaker" element={<CircuitBreakerPage />} />
            <Route path="ratelimit" element={<RateLimitPage />} />
            <Route path="metrics" element={<MetricsPage />} />
            <Route path="help" element={<HelpPage />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
