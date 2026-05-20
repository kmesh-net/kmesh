export interface NodeItem {
  name: string
  status: string
  roles: string[]
  age: string
  kernel?: string
  osImage?: string
  internalIP?: string
  labels?: Record<string, string>
}

export interface ClusterNodesResponse {
  nodes: NodeItem[]
}
