export interface MetricsOverviewResponse {
  available: boolean
  message?: string
  // Kmesh L4 工作负载指标（累计值）
  workloadConnOpened: number
  workloadConnClosed: number
  workloadRecvBytes: number
  workloadSentBytes: number
  workloadConnFailed: number
  // Kmesh L4 服务指标（累计值）
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
