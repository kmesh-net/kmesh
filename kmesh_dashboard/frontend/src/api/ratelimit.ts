import { get, post } from './client'
import type {
  RateLimitListResponse,
  RateLimitApplyRequest,
  RateLimitApplyResponse,
  RateLimitDeleteRequest,
} from '@/types/ratelimit'

export function getRateLimitList(namespace?: string) {
  const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''
  return get<RateLimitListResponse>(`/ratelimit/list${q}`)
}

export function applyRateLimit(req: RateLimitApplyRequest) {
  return post<RateLimitApplyResponse>('/ratelimit/apply', req)
}

export function deleteRateLimit(req: RateLimitDeleteRequest) {
  return post<{ message: string }>('/ratelimit/delete', req)
}
