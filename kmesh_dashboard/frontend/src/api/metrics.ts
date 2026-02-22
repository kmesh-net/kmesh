import { get } from './client'
import type { MetricsOverviewResponse, MetricsDatasourceResponse } from '@/types/metrics'

export function getMetricsDatasource() {
  return get<MetricsDatasourceResponse>('/metrics/datasource')
}

export function getMetricsOverview(params: {
  namespace?: string
  start?: number
  end?: number
  step?: number
}) {
  const sp = new URLSearchParams()
  if (params.namespace) sp.set('namespace', params.namespace)
  if (params.start != null) sp.set('start', String(params.start))
  if (params.end != null) sp.set('end', String(params.end))
  if (params.step != null) sp.set('step', String(params.step))
  const q = sp.toString()
  return get<MetricsOverviewResponse>(`/metrics/overview${q ? `?${q}` : ''}`)
}
