import { Tabs } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import WaypointListPage from './WaypointListPage'
import WaypointApplyPage from './WaypointApplyPage'

export default function WaypointPage() {
  const { can } = useAuth()
  const items = [
    { key: 'list', label: '列表与状态', children: <WaypointListPage /> },
    ...(can('waypoint', 'write') ? [{ key: 'apply', label: '安装 Waypoint', children: <WaypointApplyPage /> }] : []),
  ]
  return <Tabs items={items} />
}
