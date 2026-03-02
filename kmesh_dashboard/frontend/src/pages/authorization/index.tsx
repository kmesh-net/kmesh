import { Tabs } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import AuthorizationListPage from './AuthorizationListPage'
import AuthorizationFormPage from './AuthorizationFormPage'

export default function AuthorizationPage() {
  const { can } = useAuth()
  const items = [
    { key: 'list', label: '策略列表', children: <AuthorizationListPage /> },
    ...(can('authorization', 'write')
      ? [{ key: 'form', label: '配置授权策略', children: <AuthorizationFormPage /> }]
      : []),
  ]
  return <Tabs items={items} />
}
