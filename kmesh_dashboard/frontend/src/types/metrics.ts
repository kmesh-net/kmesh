export interface MetricsPoint {
  time: number
  value: number
}

export interface MetricsOverviewResponse {
  available: boolean
  message?: string
  // Kmesh L4
  connOpenedRate: MetricsPoint[]
  connClosedRate: MetricsPoint[]
  bytesSentRate: MetricsPoint[]
  bytesRecvRate: MetricsPoint[]
  connFailedRate: MetricsPoint[]
  // Istio L7（可选）
  rps: MetricsPoint[]
  errorRate: MetricsPoint[]
  latencyP50: MetricsPoint[]
  latencyP95: MetricsPoint[]
  latencyP99: MetricsPoint[]
}

export interface MetricsDatasourceResponse {
  available: boolean
  url?: string
  message?: string
}
