import { Tabs } from 'antd'
import CircuitBreakerListPage from './CircuitBreakerListPage'
import CircuitBreakerFormPage from './CircuitBreakerFormPage'

export default function CircuitBreakerPage() {
  return (
    <Tabs
      items={[
        { key: 'list', label: '策略列表', children: <CircuitBreakerListPage /> },
        { key: 'form', label: '配置熔断', children: <CircuitBreakerFormPage /> },
      ]}
    />
  )
}
