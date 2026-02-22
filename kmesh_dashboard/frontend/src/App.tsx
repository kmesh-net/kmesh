import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/layout/Layout'
import ClusterNodesPage from './pages/cluster/ClusterNodesPage'
import WaypointPage from './pages/waypoint'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/cluster/nodes" replace />} />
          <Route path="cluster/nodes" element={<ClusterNodesPage />} />
          <Route path="waypoint" element={<WaypointPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
