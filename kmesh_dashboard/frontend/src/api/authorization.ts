import { get, post } from './client'
import type {
  AuthorizationPolicyListResponse,
  AuthorizationPolicyApplyRequest,
  AuthorizationPolicyApplyResponse,
  AuthorizationPolicyDeleteRequest,
} from '@/types/authorization'

export function getAuthorizationList(namespace?: string) {
  const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''
  return get<AuthorizationPolicyListResponse>(`/authorization/list${q}`)
}

export function applyAuthorizationPolicy(req: AuthorizationPolicyApplyRequest) {
  return post<AuthorizationPolicyApplyResponse>('/authorization/apply', req)
}

export function deleteAuthorizationPolicy(req: AuthorizationPolicyDeleteRequest) {
  return post<{ message: string }>('/authorization/delete', req)
}
