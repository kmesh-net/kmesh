import { Navigate, useLocation } from 'react-router-dom'
import { Spin } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import { getToken } from '@/stores/authStore'

/** 未登录时重定向到 /login，已登录则渲染子组件 */
export default function RequireAuth({ children }: { children: React.ReactNode }) {
  const { ready } = useAuth()
  const location = useLocation()
  const token = getToken()

  if (!ready) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}><Spin size="large" /></div>
  if (!token) return <Navigate to="/login" state={{ from: location }} replace />
  return <>{children}</>
}
