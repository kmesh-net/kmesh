export interface WaypointItem {
  namespace: string
  name: string
  revision: string
  programmed: string
  trafficFor?: string
  gatewayUID?: string
}

export interface WaypointStatusItem extends WaypointItem {
  conditions?: { type: string; status: string; reason?: string; message?: string }[]
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
