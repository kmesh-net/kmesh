import { useEffect, useState } from 'react'
import { Card, Spin, Alert, Button } from 'antd'
import { LinkOutlined } from '@ant-design/icons'
import { getConfig } from '@/api/config'

/** 服务拓扑页：跳转到 Kiali，需配置 KIALI_URL 环境变量 */
export default function TopologyPage() {
  const [loading, setLoading] = useState(true)
  const [kialiUrl, setKialiUrl] = useState<string>('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getConfig()
      .then((c) => {
        setKialiUrl(c.kialiUrl)
        setLoading(false)
      })
      .catch(() => {
        setError('获取 Kiali 地址失败')
        setLoading(false)
      })
  }, [])

  if (loading) {
    return (
      <Card title="服务拓扑">
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin size="large" tip="加载中..." />
        </div>
      </Card>
    )
  }

  if (!kialiUrl) {
    return (
      <Card title="服务拓扑">
        <Alert
          type="warning"
          message="未配置 Kiali"
          description="请设置 KIALI_URL 环境变量后启动后端，例如：export KIALI_URL=http://kiali.kmesh-system:20001"
          showIcon
        />
      </Card>
    )
  }

  if (error) {
    return (
      <Card title="服务拓扑">
        <Alert type="error" message={error} showIcon />
      </Card>
    )
  }

  return (
    <Card title="服务拓扑">
      <div style={{ textAlign: 'center', padding: 48 }}>
        <p style={{ marginBottom: 24, color: '#666' }}>
          点击下方按钮在新窗口打开 Kiali 服务拓扑
        </p>
        <Button
          type="primary"
          size="large"
          icon={<LinkOutlined />}
          href={kialiUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          打开 Kiali
        </Button>
      </div>
    </Card>
  )
}
