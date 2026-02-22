import { Tabs } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import RateLimitListPage from './RateLimitListPage'
import RateLimitFormPage from './RateLimitFormPage'

export default function RateLimitPage() {
  const { can } = useAuth()
  const items = [
    { key: 'list', label: '策略列表', children: <RateLimitListPage /> },
    ...(can('ratelimit', 'write') ? [{ key: 'form', label: '配置限流', children: <RateLimitFormPage /> }] : []),
  ]
  return <Tabs items={items} />
}
