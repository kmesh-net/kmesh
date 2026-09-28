import { get } from './client'

export interface DocsListResponse {
  docs: string[]
}

/** Fetch the document list. */
export async function getDocsList(): Promise<DocsListResponse> {
  return get<DocsListResponse>('/docs')
}

/** Fetch raw Markdown for one document; returns the English version when lang is en. */
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
