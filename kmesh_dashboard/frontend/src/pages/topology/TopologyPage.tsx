import { useEffect, useState } from 'react'
import { Card, Spin, Alert, Button } from 'antd'
import { LinkOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'
import { getConfig } from '@/api/config'

export default function TopologyPage() {
  const { t } = useTranslation()
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
        setError(t('topology.kialiUrlFailed'))
        setLoading(false)
      })
  }, [])

  if (loading) {
    return (
      <Card title={t('topology.title')}>
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin size="large" tip={t('common.loading')} />
        </div>
      </Card>
    )
  }

  if (!kialiUrl) {
    return (
      <Card title={t('topology.title')}>
        <Alert
          type="warning"
          message={t('topology.noKiali')}
          description={t('topology.kialiEnvTip')}
          showIcon
        />
      </Card>
    )
  }

  if (error) {
    return (
      <Card title={t('topology.title')}>
        <Alert type="error" message={error} showIcon />
      </Card>
    )
  }

  return (
    <Card title={t('topology.title')}>
      <div style={{ textAlign: 'center', padding: 48 }}>
        <p style={{ marginBottom: 24, color: '#666' }}>
          {t('topology.openKialiDesc')}
        </p>
        <Button
          type="primary"
          size="large"
          icon={<LinkOutlined />}
          href={kialiUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t('topology.openKiali')}
        </Button>
      </div>
    </Card>
  )
}
