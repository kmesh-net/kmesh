import { get } from './client'
import type {
  MetricsOverviewResponse,
  MetricsDatasourceResponse,
  AccesslogResponse,
} from '@/types/metrics'

export function getMetricsDatasource() {
  return get<MetricsDatasourceResponse>('/metrics/datasource')
}

export function getMetricsOverview(params?: { namespace?: string }) {
  const sp = new URLSearchParams()
  if (params?.namespace) sp.set('namespace', params.namespace)
  const q = sp.toString()
  return get<MetricsOverviewResponse>(`/metrics/overview${q ? `?${q}` : ''}`)
}

export function getAccesslog(params?: { pod?: string; namespace?: string; tail?: number }) {
  const sp = new URLSearchParams()
  if (params?.pod) sp.set('pod', params.pod)
  if (params?.namespace) sp.set('namespace', params.namespace)
  if (params?.tail != null) sp.set('tail', String(params.tail))
  const q = sp.toString()
  return get<AccesslogResponse>(`/metrics/accesslog${q ? `?${q}` : ''}`)
}

export function getKmeshPods(params?: { namespace?: string }) {
  const sp = new URLSearchParams()
  if (params?.namespace) sp.set('namespace', params.namespace)
  const q = sp.toString()
  return get<{ pods: { name: string; node: string; status: string }[]; message?: string }>(
    `/metrics/kmesh-pods${q ? `?${q}` : ''}`
  )
}
