import { get } from './client'
import type { ClusterNodesResponse } from '@/types/cluster'

export function getClusterNodes() {
  return get<ClusterNodesResponse>('/cluster/nodes')
}

export function getNamespaceList() {
  return get<{ items: string[] }>('/cluster/namespaces')
}
