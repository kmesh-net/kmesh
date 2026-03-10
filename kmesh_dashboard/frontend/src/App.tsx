import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import ClusterNodesPage from './pages/cluster/ClusterNodesPage'
import TopologyPage from './pages/topology/TopologyPage'
import WaypointPage from './pages/waypoint'
import CircuitBreakerPage from './pages/circuitbreaker'
import AuthorizationPage from './pages/authorization'
import RateLimitPage from './pages/ratelimit'
import MetricsPage from './pages/metrics/MetricsPage'
import HelpPage from './pages/help/HelpPage'
function App() {
  return (
    <BrowserRouter>
      <Routes>
          <Route
            path="/"
            element={<Layout />}
          >
            <Route index element={<Navigate to="/cluster/nodes" replace />} />
            <Route path="cluster/nodes" element={<ClusterNodesPage />} />
            <Route path="topology" element={<TopologyPage />} />
            <Route path="waypoint" element={<WaypointPage />} />
            <Route path="circuitbreaker" element={<CircuitBreakerPage />} />
            <Route path="authorization" element={<AuthorizationPage />} />
            <Route path="ratelimit" element={<RateLimitPage />} />
            <Route path="metrics" element={<MetricsPage />} />
            <Route path="help" element={<HelpPage />} />
          </Route>
        </Routes>
    </BrowserRouter>
  )
}

export default App
