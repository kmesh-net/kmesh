import { get } from './client'

export interface PodDetailResponse {
  namespace: string
  name: string
  phase: string
  reason?: string
  message?: string
  node?: string
  podIP?: string
  startTime?: string
  labels?: Record<string, string>
  annotations?: Record<string, string>
  containers?: Array<{
    name: string
    image?: string
    ready: boolean
    restartCount: number
    state: string
    reason?: string
    message?: string
    lastState?: string
    lastExitCode?: number
    lastFinishedAt?: string
    exitCode?: number
    startedAt?: string
    finishedAt?: string
  }>
  conditions?: Array<{
    type: string
    status: string
    reason?: string
    message?: string
    lastTransitionTime?: string
  }>
  events?: Array<{
    firstSeen?: string
    lastSeen: string
    type: string
    reason: string
    message: string
    count?: number
    source?: string
  }>
  error?: string
}

export interface PodLogsResponse {
  namespace: string
  name: string
  container?: string
  lines: string[]
  error?: string
}

export function getPodDetail(namespace: string, name: string) {
  const q = `?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}`
  return get<PodDetailResponse>(`/pod/detail${q}`)
}

export function getPodLogs(namespace: string, name: string, options?: { container?: string; tail?: number }) {
  const params = new URLSearchParams({ namespace, name })
  if (options?.container) params.set('container', options.container)
  if (options?.tail) params.set('tail', String(options.tail))
  return get<PodLogsResponse>(`/pod/logs?${params}`)
}
