export interface CircuitBreakerItem {
  namespace: string
  name: string
  host: string
  maxConnections?: number
  maxPendingRequests?: number
  maxRequests?: number
  maxRetries?: number
  connectTimeoutMs?: number
  maxRequestsPerConnection?: number
}

export interface CircuitBreakerListResponse {
  items: CircuitBreakerItem[]
}

export interface CircuitBreakerApplyRequest {
  namespace: string
  name: string
  host: string
  maxConnections?: number
  maxPendingRequests?: number
  maxRequests?: number
  maxRetries?: number
  connectTimeoutMs?: number
  maxRequestsPerConnection?: number
}

export interface CircuitBreakerApplyResponse {
  namespace: string
  name: string
  message: string
}

export interface CircuitBreakerDeleteRequest {
  namespace: string
  name: string
}

/** 预设模板：保守 / 标准 / 激进 */
export const CIRCUIT_BREAKER_PRESETS: Record<string, Partial<CircuitBreakerApplyRequest>> = {
  conservative: {
    maxConnections: 10,
    maxPendingRequests: 20,
    maxRequests: 50,
    maxRetries: 2,
    connectTimeoutMs: 500,
    maxRequestsPerConnection: 1,
  },
  standard: {
    maxConnections: 100,
    maxPendingRequests: 200,
    maxRequests: 500,
    maxRetries: 3,
    connectTimeoutMs: 1000,
    maxRequestsPerConnection: 2,
  },
  aggressive: {
    maxConnections: 1000,
    maxPendingRequests: 2000,
    maxRequests: 5000,
    maxRetries: 5,
    connectTimeoutMs: 3000,
    maxRequestsPerConnection: 10,
  },
}
