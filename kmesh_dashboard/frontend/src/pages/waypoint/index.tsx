import { Tabs } from 'antd'
import WaypointListPage from './WaypointListPage'
import WaypointApplyPage from './WaypointApplyPage'

export default function WaypointPage() {
  return (
    <Tabs
      items={[
        { key: 'list', label: '列表与状态', children: <WaypointListPage /> },
        { key: 'apply', label: '安装 Waypoint', children: <WaypointApplyPage /> },
      ]}
    />
  )
}
