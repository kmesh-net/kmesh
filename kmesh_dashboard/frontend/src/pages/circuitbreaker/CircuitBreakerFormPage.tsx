import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Form, Input, Select, InputNumber, Button, Alert, Space } from 'antd'
import { ThunderboltOutlined } from '@ant-design/icons'
import { applyCircuitBreaker } from '@/api/circuitbreaker'
import { getServiceList } from '@/api/services'
import type { ServiceItem } from '@/api/services'
import type { CircuitBreakerApplyRequest } from '@/types/circuitbreaker'

interface CircuitBreakerFormPageProps {
  selectedNamespace: string
  namespaceOptions: string[]
}

export default function CircuitBreakerFormPage({ selectedNamespace }: CircuitBreakerFormPageProps) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [services, setServices] = useState<ServiceItem[]>([])
  const [servicesLoading, setServicesLoading] = useState(false)
  const [form] = Form.useForm<CircuitBreakerApplyRequest>()

  useEffect(() => {
    setServicesLoading(true)
    getServiceList(selectedNamespace || undefined)
      .then((res) => setServices(res.items))
      .catch(() => setServices([]))
      .finally(() => setServicesLoading(false))
  }, [selectedNamespace])

  const onFinish = async (values: CircuitBreakerApplyRequest) => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const req: CircuitBreakerApplyRequest = {
        namespace: selectedNamespace || 'default',
        name: values.name,
        host: values.host,
      }
      if (values.maxConnections != null && values.maxConnections > 0) req.maxConnections = values.maxConnections
      if (values.maxPendingRequests != null && values.maxPendingRequests > 0) req.maxPendingRequests = values.maxPendingRequests
      if (values.maxRequests != null && values.maxRequests > 0) req.maxRequests = values.maxRequests
      if (values.maxRetries != null && values.maxRetries > 0) req.maxRetries = values.maxRetries
      if (values.connectTimeoutMs != null && values.connectTimeoutMs > 0) req.connectTimeoutMs = values.connectTimeoutMs
      if (values.maxRequestsPerConnection != null && values.maxRequestsPerConnection > 0) req.maxRequestsPerConnection = values.maxRequestsPerConnection
      const res = await applyCircuitBreaker(req)
      setSuccess(res.message)
      form.resetFields()
    } catch (e) {
      setError(e instanceof Error ? e.message : t('common.applyFailed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title={t('circuitbreaker.config')}>
      <p style={{ color: '#666', marginBottom: 16 }}>
        {t('circuitbreaker.formDesc')}
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
      >
        <Form.Item name="name" label={t('circuitbreaker.drName')} rules={[{ required: true }]}>
          <Input placeholder={t('circuitbreaker.drNamePlaceholder')} />
        </Form.Item>
        <Form.Item
          name="host"
          label={t('circuitbreaker.hostLabel')}
          rules={[{ required: true }]}
          extra={t('circuitbreaker.hostExtra')}
        >
          <Input placeholder={t('circuitbreaker.hostPlaceholder')} />
        </Form.Item>
        <Form.Item label={t('circuitbreaker.selectFromCluster')}>
          <Select
            placeholder={t('circuitbreaker.selectServicePlaceholder')}
            loading={servicesLoading}
            allowClear
            style={{ width: '100%' }}
            options={services.map((s) => ({
              label: s.name,
              value: `${s.namespace}/${s.name}`,
            }))}
            onChange={(value: string | null) => {
              if (!value) return
              const [ns, name] = value.split('/')
              const host = ns === selectedNamespace ? name : `${name}.${ns}.svc.cluster.local`
              form.setFieldsValue({ host })
            }}
          />
        </Form.Item>
        <Form.Item name="maxConnections" label={t('circuitbreaker.maxConnections')}>
          <InputNumber min={1} max={100000} style={{ width: '100%' }} placeholder="TCP" />
        </Form.Item>
        <Form.Item name="maxPendingRequests" label={t('circuitbreaker.maxPendingRequests')}>
          <InputNumber min={1} max={100000} style={{ width: '100%' }} placeholder="HTTP" />
        </Form.Item>
        <Form.Item name="maxRequests" label={t('circuitbreaker.maxRequests')}>
          <InputNumber min={1} max={100000} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="maxRetries" label={t('circuitbreaker.maxRetries')}>
          <InputNumber min={0} max={100} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="connectTimeoutMs" label={t('circuitbreaker.connectTimeout')}>
          <InputNumber min={1} max={300000} style={{ width: '100%' }} placeholder="connectTimeout" />
        </Form.Item>
        <Form.Item name="maxRequestsPerConnection" label={t('circuitbreaker.maxRequestsPerConn')}>
          <InputNumber min={1} max={1000} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<ThunderboltOutlined />} loading={loading}>
              {t('common.apply')}
            </Button>
            <Button onClick={() => form.resetFields()}>{t('common.reset')}</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
