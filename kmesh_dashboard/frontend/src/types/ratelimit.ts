export interface RateLimitItem {
  namespace: string
  name: string
  statPrefix?: string
  maxTokens?: number
  tokensPerFill?: number
  fillIntervalSec?: number
  workloadSelector?: Record<string, string>
}

export interface RateLimitListResponse {
  items: RateLimitItem[]
}

export interface RateLimitApplyRequest {
  namespace: string
  name: string
  statPrefix?: string
  maxTokens: number
  tokensPerFill: number
  fillIntervalSec: number
  workloadSelector?: Record<string, string>
}

export interface RateLimitApplyResponse {
  namespace: string
  name: string
  message: string
}

export interface RateLimitDeleteRequest {
  namespace: string
  name: string
}
