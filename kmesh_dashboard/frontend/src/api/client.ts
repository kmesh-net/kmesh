const API_BASE = '/api'
const LANG_KEY = 'kmesh_dashboard_lang'

function getLangHeader(): string {
  if (typeof localStorage === 'undefined') return 'zh'
  const stored = localStorage.getItem(LANG_KEY)
  if (stored === 'en' || stored === 'zh') return stored
  return 'zh'
}

export async function get<T>(path: string): Promise<T> {
  const lang = getLangHeader()
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Accept-Language': lang === 'en' ? 'en' : 'zh-CN,zh' },
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || `HTTP ${res.status}`)
  }
  return res.json()
}

export async function post<T>(path: string, body: object): Promise<T> {
  const lang = getLangHeader()
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept-Language': lang === 'en' ? 'en' : 'zh-CN,zh',
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || `HTTP ${res.status}`)
  }
  return res.json()
}
