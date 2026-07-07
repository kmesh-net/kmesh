export interface MetricsOverviewResponse {
  available: boolean
  message?: string
  // Kmesh L4 workload metrics (cumulative values)
  workloadConnOpened: number
  workloadConnClosed: number
  workloadRecvBytes: number
  workloadSentBytes: number
  workloadConnFailed: number
  // Kmesh L4 service metrics (cumulative values)
  serviceConnOpened: number
  serviceConnClosed: number
  serviceRecvBytes: number
  serviceSentBytes: number
  serviceConnFailed: number
}

export interface MetricsDatasourceResponse {
  available: boolean
  url?: string
  message?: string
}

export interface AccesslogEntry {
  pod: string
  node?: string
  content: string
}

export interface AccesslogResponse {
  entries: AccesslogEntry[]
  podsQueried?: string[]
  message?: string
}
