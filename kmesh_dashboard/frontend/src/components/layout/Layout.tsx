import React from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { Layout as AntLayout, Menu, Select } from 'antd'
import { ClusterOutlined, ApartmentOutlined, GatewayOutlined, ThunderboltOutlined, SafetyOutlined, FilterOutlined, LineChartOutlined, BookOutlined, GlobalOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'
import type { Lang } from '@/i18n'

const { Header, Content } = AntLayout

const navKeys = ['/cluster/nodes', '/topology', '/waypoint', '/circuitbreaker', '/authorization', '/ratelimit', '/metrics', '/help'] as const
const navIcons = [ClusterOutlined, ApartmentOutlined, GatewayOutlined, ThunderboltOutlined, SafetyOutlined, FilterOutlined, LineChartOutlined, BookOutlined]
const navTKeys = ['nav.cluster', 'nav.topology', 'nav.waypoint', 'nav.circuitbreaker', 'nav.authorization', 'nav.ratelimit', 'nav.metrics', 'nav.help'] as const

export default function Layout() {
  const { t, i18n } = useTranslation()
  const location = useLocation()
  const selected = navKeys.find((k) => location.pathname.startsWith(k)) ?? '/cluster/nodes'

  const navItems = navKeys.map((key, i) => ({
    key,
    icon: navIcons[i] ? React.createElement(navIcons[i]) : undefined,
    label: <Link to={key}>{t(navTKeys[i])}</Link>,
  }))

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <Menu
          theme="dark"
          mode="horizontal"
          selectedKeys={[selected]}
          items={navItems}
          style={{ flex: 1, minWidth: 0 }}
        />
        <Select
          value={i18n.language as Lang}
          onChange={(v) => i18n.changeLanguage(v)}
          options={[
            { value: 'zh', label: '中文' },
            { value: 'en', label: 'English' },
          ]}
          suffixIcon={<GlobalOutlined style={{ color: 'rgba(255,255,255,0.85)' }} />}
          style={{ width: 110 }}
          variant="borderless"
          popupMatchSelectWidth={false}
          dropdownStyle={{ minWidth: 110 }}
          className="header-lang-select"
        />
      </Header>
      <Content style={{ padding: 24 }}>
        <Outlet />
      </Content>
    </AntLayout>
  )
}
