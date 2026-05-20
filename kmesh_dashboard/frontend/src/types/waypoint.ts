export interface WaypointItem {
  namespace: string
  name: string
  revision: string
  programmed: string
  trafficFor?: string
  gatewayUID?: string
}

export interface WaypointPodInfo {
  name: string
  phase: string
  ready: boolean
  reason?: string
}

export interface WaypointPodStatus {
  ready: number
  total: number
  phase: string
  message: string
  pods?: WaypointPodInfo[]
}

export interface WaypointStatusItem extends WaypointItem {
  conditions?: { type: string; status: string; reason?: string; message?: string }[]
  podStatus?: WaypointPodStatus
}

export interface WaypointListResponse {
  items: WaypointItem[]
}

export interface WaypointStatusResponse {
  items: WaypointStatusItem[]
}

export interface WaypointApplyRequest {
  namespace: string
  name: string
  trafficFor?: string
  enrollNamespace?: boolean
  overwrite?: boolean
  waitReady?: boolean
  revision?: string
  proxyImage?: string
}

export interface WaypointApplyResponse {
  namespace: string
  name: string
  message: string
}

export interface WaypointDeleteRequest {
  namespace: string
  names: string[]
}

export interface WaypointDeleteResponse {
  deleted: string[]
  errors?: string[]
}
