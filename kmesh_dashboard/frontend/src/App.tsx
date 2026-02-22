import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import ClusterNodesPage from './pages/cluster/ClusterNodesPage'
import WaypointPage from './pages/waypoint'
import CircuitBreakerPage from './pages/circuitbreaker'
import RateLimitPage from './pages/ratelimit'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/cluster/nodes" replace />} />
          <Route path="cluster/nodes" element={<ClusterNodesPage />} />
          <Route path="waypoint" element={<WaypointPage />} />
          <Route path="circuitbreaker" element={<CircuitBreakerPage />} />
          <Route path="ratelimit" element={<RateLimitPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
