import { Tabs } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import CircuitBreakerListPage from './CircuitBreakerListPage'
import CircuitBreakerFormPage from './CircuitBreakerFormPage'

export default function CircuitBreakerPage() {
  const { can } = useAuth()
  const items = [
    { key: 'list', label: '策略列表', children: <CircuitBreakerListPage /> },
    ...(can('circuitbreaker', 'write') ? [{ key: 'form', label: '配置熔断', children: <CircuitBreakerFormPage /> }] : []),
  ]
  return <Tabs items={items} />
}
