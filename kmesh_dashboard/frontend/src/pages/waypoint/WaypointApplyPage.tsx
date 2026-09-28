import { useState } from 'react'
import { Card, Form, Input, Select, Button, Switch, Alert, Space } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'
import { applyWaypoint } from '@/api/waypoint'

interface WaypointApplyPageProps {
  selectedNamespace: string
  namespaceOptions: string[]
}

export default function WaypointApplyPage({ selectedNamespace }: WaypointApplyPageProps) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [form] = Form.useForm()

  const trafficOptions = [
    { value: '', label: t('waypoint.trafficDefault') },
    { value: 'service', label: 'Service' },
    { value: 'workload', label: 'Workload' },
    { value: 'all', label: 'All' },
    { value: 'none', label: 'None' },
  ]

  const onFinish = async (values: Record<string, unknown>) => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const res = await applyWaypoint({
        namespace: selectedNamespace,
        name: (values.name as string) || 'waypoint',
        trafficFor: (values.trafficFor as string) || undefined,
        enrollNamespace: !!values.enrollNamespace,
        overwrite: !!values.overwrite,
        waitReady: !!values.waitReady,
        revision: (values.revision as string) || undefined,
        proxyImage: (values.proxyImage as string) || undefined,
      })
      setSuccess(res.message)
      form.resetFields()
    } catch (e) {
      setError(e instanceof Error ? e.message : t('waypoint.installFailed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title={t('waypoint.installTitle')}>
      <p style={{ color: '#666', marginBottom: 16 }}>
        {t('waypoint.installDesc')}
      </p>
      {error && (
        <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
      )}
      {success && (
        <Alert type="success" message={success} showIcon style={{ marginBottom: 16 }} />
      )}
      <Form
        form={form}
        layout="vertical"
        onFinish={onFinish}
        initialValues={{
          name: 'waypoint',
          trafficFor: '',
          enrollNamespace: false,
          overwrite: false,
          waitReady: false,
        }}
      >
        <Form.Item name="name" label={t('waypoint.nameLabel')} rules={[{ required: true }]}>
          <Input placeholder={t('waypoint.namePlaceholder')} />
        </Form.Item>
        <Form.Item name="trafficFor" label={t('waypoint.trafficFor')}>
          <Select options={trafficOptions} placeholder={t('waypoint.trafficPlaceholder')} />
        </Form.Item>
        <Form.Item name="enrollNamespace" label={t('waypoint.enrollNamespace')} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="overwrite" label={t('waypoint.overwrite')} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="waitReady" label={t('waypoint.waitReady')} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="revision" label={t('waypoint.revision')}>
          <Input placeholder={t('common.optional')} />
        </Form.Item>
        <Form.Item name="proxyImage" label={t('waypoint.proxyImage')}>
          <Input placeholder={t('waypoint.proxyPlaceholder')} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<PlusOutlined />} loading={loading}>
              {t('waypoint.installBtn')}
            </Button>
            <Button onClick={() => form.resetFields()}>{t('common.reset')}</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
