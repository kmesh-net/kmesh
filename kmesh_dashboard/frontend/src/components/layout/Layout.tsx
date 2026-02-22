import { Outlet, Link, useLocation } from 'react-router-dom'
import { Layout as AntLayout, Menu } from 'antd'
import { ClusterOutlined, GatewayOutlined, ThunderboltOutlined, FilterOutlined } from '@ant-design/icons'

const { Header, Content } = AntLayout

const navItems = [
  { key: '/cluster/nodes', icon: <ClusterOutlined />, label: <Link to="/cluster/nodes">集群节点</Link> },
  { key: '/waypoint', icon: <GatewayOutlined />, label: <Link to="/waypoint">Waypoint</Link> },
  { key: '/circuitbreaker', icon: <ThunderboltOutlined />, label: <Link to="/circuitbreaker">熔断</Link> },
  { key: '/ratelimit', icon: <FilterOutlined />, label: <Link to="/ratelimit">限流</Link> },
]

export default function Layout() {
  const location = useLocation()
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
      </Header>
      <Content style={{ padding: 24 }}>
        <Outlet />
      </Content>
    </AntLayout>
  )
}
