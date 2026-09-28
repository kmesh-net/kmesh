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
