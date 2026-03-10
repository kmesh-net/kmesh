import { get } from './client'

export interface DocsListResponse {
  docs: string[]
}

/** 获取文档列表 */
export async function getDocsList(): Promise<DocsListResponse> {
  return get<DocsListResponse>('/docs')
}

/** 获取单个文档的 Markdown 内容（原始文本），lang 为 en 时返回英文版 */
export async function getDocContent(name: string, lang?: string): Promise<string> {
  const headers: HeadersInit = {}
  if (lang === 'en') {
    headers['X-Doc-Lang'] = 'en'
  }
  const url = `/api/docs/${name}${lang === 'en' ? '?lang=en' : ''}`
  const res = await fetch(url, { headers, cache: 'no-store' })
  if (!res.ok) {
    throw new Error(res.status === 404 ? '文档不存在' : `HTTP ${res.status}`)
  }
  return res.text()
}
