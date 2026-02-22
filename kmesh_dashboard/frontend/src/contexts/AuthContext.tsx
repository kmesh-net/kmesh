import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getToken, setToken, setOnUnauthorized } from '@/stores/authStore'
import { me } from '@/api/auth'
import type { LoginResponse } from '@/api/auth'

type AuthState = {
  user: string | null
  role: string | null
  loading: boolean
  ready: boolean
}

const defaultState: AuthState = { user: null, role: null, loading: false, ready: false }

const AuthContext = createContext<{
  user: string | null
  role: string | null
  loading: boolean
  ready: boolean
  login: (res: LoginResponse) => void
  logout: () => void
  can: (resource: string, action: string) => boolean
}>({
  ...defaultState,
  login: () => {},
  logout: () => {},
  can: () => false,
})

/** 与后端 Casbin policy 对齐：按角色判断是否有 resource 的 action 权限 */
function canDo(role: string, resource: string, action: string): boolean {
  if (role === 'admin') return true
  if (role === 'reader') {
    return ['cluster', 'services', 'metrics', 'waypoint', 'circuitbreaker', 'ratelimit', 'auth'].includes(resource) && action === 'read'
  }
  if (role === 'editor') {
    if (resource === 'auth' && action === 'read') return true
    if (['cluster', 'services', 'metrics'].includes(resource) && action === 'read') return true
    if (['waypoint', 'circuitbreaker', 'ratelimit'].includes(resource)) return true
  }
  return false
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>(defaultState)
  const navigate = useNavigate()

  const loadUser = useCallback(async () => {
    const token = getToken()
    if (!token) {
      setState((s) => ({ ...s, user: null, role: null, ready: true }))
      return
    }
    setState((s) => ({ ...s, loading: true }))
    try {
      const res = await me()
      setState({ user: res.user, role: res.role, loading: false, ready: true })
    } catch {
      setToken(null)
      setState({ user: null, role: null, loading: false, ready: true })
    }
  }, [])

  useEffect(() => {
    setOnUnauthorized(() => {
      setState({ user: null, role: null, loading: false, ready: true })
      navigate('/login', { replace: true })
    })
  }, [navigate])

  useEffect(() => {
    loadUser()
  }, [loadUser])

  const login = useCallback((res: LoginResponse) => {
    setToken(res.token)
    setState({ user: res.user, role: res.role, loading: false, ready: true })
    navigate('/', { replace: true })
  }, [navigate])

  const logout = useCallback(() => {
    setToken(null)
    setState({ user: null, role: null, loading: false, ready: true })
    navigate('/login', { replace: true })
  }, [navigate])

  const can = useCallback((resource: string, action: string) => {
    if (!state.role) return false
    return canDo(state.role, resource, action)
  }, [state.role])

  return (
    <AuthContext.Provider
      value={{
        user: state.user,
        role: state.role,
        loading: state.loading,
        ready: state.ready,
        login,
        logout,
        can,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
