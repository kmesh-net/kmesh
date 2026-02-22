import { get, post } from './client'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  user: string
  role: string
  expire: number
}

export interface MeResponse {
  user: string
  role: string
}

export function login(body: LoginRequest): Promise<LoginResponse> {
  return post<LoginResponse>('/auth/login', body)
}

export function me(): Promise<MeResponse> {
  return get<MeResponse>('/auth/me')
}
