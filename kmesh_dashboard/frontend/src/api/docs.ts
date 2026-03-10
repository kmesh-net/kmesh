import { get } from './client'

export interface DocsListResponse {
  docs: string[]
}

/** 获取文档列表 */
export async function getDocsList(): Promise<DocsListResponse> {
  return get<DocsListResponse>('/docs')
}

/** 获取单个文档的 Markdown 内容（原始文本） */
export async function getDocContent(name: string): Promise<string> {
  const res = await fetch(`/api/docs/${name}`)
  if (!res.ok) {
    throw new Error(res.status === 404 ? '文档不存在' : `HTTP ${res.status}`)
  }
  return res.text()
}
