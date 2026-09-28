import { get, post } from './client'
import type {
  CircuitBreakerListResponse,
  CircuitBreakerApplyRequest,
  CircuitBreakerApplyResponse,
  CircuitBreakerDeleteRequest,
} from '@/types/circuitbreaker'

export function getCircuitBreakerList(namespace?: string) {
  const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''
  return get<CircuitBreakerListResponse>(`/circuitbreaker/list${q}`)
}

export function applyCircuitBreaker(req: CircuitBreakerApplyRequest) {
  return post<CircuitBreakerApplyResponse>('/circuitbreaker/apply', req)
}

export function deleteCircuitBreaker(req: CircuitBreakerDeleteRequest) {
  return post<{ message: string }>('/circuitbreaker/delete', req)
}
