import { get, post } from './client'

export type CustomYamlModule = 'circuitbreaker' | 'ratelimit' | 'authorization' | 'waypoint'

export interface CustomYamlTemplateResponse {
  module: string
  yaml: string
  apiVersion: string
  kind: string
}

export interface CustomYamlValidateResponse {
  valid: boolean
  error?: string
  name?: string
  kind?: string
}

export interface CustomYamlApplyResponse {
  namespace: string
  name: string
  message: string
  error?: string
}

export function getCustomYamlTemplate(module: CustomYamlModule) {
  return get<CustomYamlTemplateResponse>(`/custom/template?module=${encodeURIComponent(module)}`)
}

export function validateCustomYaml(module: CustomYamlModule, yaml: string) {
  return post<CustomYamlValidateResponse>('/custom/validate', { module, yaml })
}

export function applyCustomYaml(module: CustomYamlModule, namespace: string, yaml: string) {
  return post<CustomYamlApplyResponse>('/custom/apply', { module, namespace, yaml })
}
