import { post } from './client'
import { get } from './client'
import type {
  WaypointListResponse,
  WaypointStatusResponse,
  WaypointApplyRequest,
  WaypointApplyResponse,
  WaypointDeleteRequest,
  WaypointDeleteResponse,
} from '@/types/waypoint'

export function getWaypointList(params: { namespace?: string; allNamespaces?: boolean }) {
  const sp = new URLSearchParams()
  if (params.namespace) sp.set('namespace', params.namespace)
  if (params.allNamespaces) sp.set('allNamespaces', 'true')
  const q = sp.toString()
  return get<WaypointListResponse>(`/waypoint/list${q ? `?${q}` : ''}`)
}

export function getWaypointStatus(namespace: string) {
  const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''
  return get<WaypointStatusResponse>(`/waypoint/status${q}`)
}

export function applyWaypoint(req: WaypointApplyRequest) {
  return post<WaypointApplyResponse>('/waypoint/apply', req)
}

export function deleteWaypoint(req: WaypointDeleteRequest) {
  return post<WaypointDeleteResponse>('/waypoint/delete', req)
}
