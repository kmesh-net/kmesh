export interface AuthorizationPolicyItem {
  namespace: string
  name: string
  action: string
  selector?: Record<string, string>
  rulesCount: number
  workloadRef?: string
  /** 规则详情（来源 IP/命名空间、目标端口/路径等） */
  rules?: AuthorizationPolicyRuleApply[]
}

export interface AuthorizationPolicyListResponse {
  items: AuthorizationPolicyItem[]
}

export interface AuthorizationPolicySource {
  ipBlocks?: string[]
  namespaces?: string[]
  principals?: string[]
}

export interface AuthorizationPolicyOperation {
  hosts?: string[]
  ports?: string[]
  paths?: string[]
  methods?: string[]
}

export interface AuthorizationPolicyFrom {
  source?: AuthorizationPolicySource
}

export interface AuthorizationPolicyTo {
  operation?: AuthorizationPolicyOperation
}

export interface AuthorizationPolicyRuleApply {
  from?: AuthorizationPolicyFrom[]
  to?: AuthorizationPolicyTo[]
}

export interface AuthorizationPolicyApplyRequest {
  namespace: string
  name: string
  action: 'ALLOW' | 'DENY'
  selector?: Record<string, string>
  rules?: AuthorizationPolicyRuleApply[]
}

export interface AuthorizationPolicyApplyResponse {
  namespace: string
  name: string
  message: string
}

export interface AuthorizationPolicyDeleteRequest {
  namespace: string
  name: string
}
