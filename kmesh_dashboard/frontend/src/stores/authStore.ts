const TOKEN_KEY = 'kmesh_dashboard_token'

let onUnauthorized: (() => void) | null = null

export function setOnUnauthorized(cb: () => void) {
  onUnauthorized = cb
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (typeof window === 'undefined') return
  if (token == null) localStorage.removeItem(TOKEN_KEY)
  else localStorage.setItem(TOKEN_KEY, token)
}

/** 清除 token 并触发未授权回调（如跳转登录） */
export function clearAuth() {
  setToken(null)
  onUnauthorized?.()
}
