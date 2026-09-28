import { get } from './client'

export interface ServiceItem {
  namespace: string
  name: string
}

export interface ServiceListResponse {
  items: ServiceItem[]
}

export function getServiceList(namespace?: string) {
  const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''
  return get<ServiceListResponse>(`/services${q}`)
}
