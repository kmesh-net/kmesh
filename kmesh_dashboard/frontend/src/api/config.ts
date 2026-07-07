export type ConfigResponse = {
  kialiUrl: string
}

export async function getConfig(): Promise<ConfigResponse> {
  const res = await fetch('/api/config')
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }
  return res.json()
}
