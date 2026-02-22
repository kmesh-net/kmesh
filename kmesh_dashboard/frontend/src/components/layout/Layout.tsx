import { Outlet, Link, useLocation } from 'react-router-dom'
import { Layout as AntLayout, Menu, Button, Space } from 'antd'
import { ClusterOutlined, GatewayOutlined, ThunderboltOutlined, FilterOutlined, LineChartOutlined, LogoutOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'

const { Header, Content } = AntLayout

const navItems = [
  { key: '/cluster/nodes', icon: <ClusterOutlined />, label: <Link to="/cluster/nodes">集群节点</Link> },
  { key: '/waypoint', icon: <GatewayOutlined />, label: <Link to="/waypoint">Waypoint</Link> },
  { key: '/circuitbreaker', icon: <ThunderboltOutlined />, label: <Link to="/circuitbreaker">熔断</Link> },
  { key: '/ratelimit', icon: <FilterOutlined />, label: <Link to="/ratelimit">限流</Link> },
  { key: '/metrics', icon: <LineChartOutlined />, label: <Link to="/metrics">指标</Link> },
]

export default function Layout() {
  const location = useLocation()
  const { user, role, logout } = useAuth()
  const selected = navItems.find((i) => location.pathname.startsWith(i.key))?.key ?? '/cluster/nodes'

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <span style={{ color: '#fff', fontWeight: 600 }}>Kmesh Dashboard</span>
        <Menu
          theme="dark"
          mode="horizontal"
          selectedKeys={[selected]}
          items={navItems}
          style={{ flex: 1, minWidth: 0 }}
        />
        <Space style={{ color: '#fff' }}>
          <span>{user} ({role})</span>
          <Button type="text" icon={<LogoutOutlined />} onClick={logout} style={{ color: 'rgba(255,255,255,0.85)' }}>
            退出
          </Button>
        </Space>
      </Header>
      <Content style={{ padding: 24 }}>
        <Outlet />
      </Content>
    </AntLayout>
  )
}
