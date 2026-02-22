import { Tabs } from 'antd'
import RateLimitListPage from './RateLimitListPage'
import RateLimitFormPage from './RateLimitFormPage'

export default function RateLimitPage() {
  return (
    <Tabs
      items={[
        { key: 'list', label: '策略列表', children: <RateLimitListPage /> },
        { key: 'form', label: '配置限流', children: <RateLimitFormPage /> },
      ]}
    />
  )
}
