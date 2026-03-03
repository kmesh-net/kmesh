import { useState, useEffect } from 'react'
import { Card, Form, Input, Select, Button, InputNumber, Alert, Space } from 'antd'
import { ThunderboltOutlined } from '@ant-design/icons'
import { applyCircuitBreaker } from '@/api/circuitbreaker'
import { getServiceList } from '@/api/services'
import type { ServiceItem } from '@/api/services'
import { CIRCUIT_BREAKER_PRESETS, type CircuitBreakerApplyRequest } from '@/types/circuitbreaker'

interface CircuitBreakerFormPageProps {
  selectedNamespace: string
  namespaceOptions: string[]
}

const PRESET_OPTIONS = [
  { value: '', label: '自定义' },
  { value: 'conservative', label: '保守（低阈值）' },
  { value: 'standard', label: '标准' },
  { value: 'aggressive', label: '激进（高阈值）' },
]

export default function CircuitBreakerFormPage({ selectedNamespace }: CircuitBreakerFormPageProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [services, setServices] = useState<ServiceItem[]>([])
  const [servicesLoading, setServicesLoading] = useState(false)
  const [form] = Form.useForm<CircuitBreakerApplyRequest & { preset?: string }>()

  useEffect(() => {
    setServicesLoading(true)
    getServiceList(selectedNamespace || undefined)
      .then((res) => setServices(res.items))
      .catch(() => setServices([]))
      .finally(() => setServicesLoading(false))
  }, [selectedNamespace])

  const onPresetChange = (preset: string) => {
    if (!preset) return
    const values = CIRCUIT_BREAKER_PRESETS[preset]
    if (values) {
      form.setFieldsValue({
        maxConnections: values.maxConnections,
        maxPendingRequests: values.maxPendingRequests,
        maxRequests: values.maxRequests,
        maxRetries: values.maxRetries,
        connectTimeoutMs: values.connectTimeoutMs,
        maxRequestsPerConnection: values.maxRequestsPerConnection,
      })
    }
  }

  const onFinish = async (values: CircuitBreakerApplyRequest & { preset?: string }) => {
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
      setError(e instanceof Error ? e.message : '应用失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="配置熔断">
      <p style={{ color: '#666', marginBottom: 16 }}>
        在<strong>当前命名空间</strong>（上方选择器）下选择预设模板或自定义阈值，对目标服务（Host）配置连接池与熔断。将写入 Istio DestinationRule（需集群已安装相应 CRD）。
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
          preset: '',
        }}
      >
        <Form.Item name="preset" label="预设模板">
          <Select
            options={PRESET_OPTIONS}
            placeholder="选择后自动填充下方阈值"
            onChange={onPresetChange}
          />
        </Form.Item>
        <Form.Item name="name" label="DestinationRule 名称" rules={[{ required: true }]}>
          <Input placeholder="例如 my-service-cb" />
        </Form.Item>
        <Form.Item
          name="host"
          label="目标 Host（服务名）"
          rules={[{ required: true }]}
          extra="可从下方「从集群选择服务」中选择，或直接输入服务名 / FQDN"
        >
          <Input placeholder="例如 reviews、httpbin.default.svc.cluster.local" />
        </Form.Item>
        <Form.Item label="从集群选择服务">
          <Select
            placeholder="先选上方命名空间，此处会列出该命名空间下的服务；选择后自动填入目标 Host"
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
        <Form.Item name="maxConnections" label="最大连接数 (maxConnections)">
          <InputNumber min={1} max={100000} style={{ width: '100%' }} placeholder="TCP" />
        </Form.Item>
        <Form.Item name="maxPendingRequests" label="最大待处理请求 (http1MaxPendingRequests)">
          <InputNumber min={1} max={100000} style={{ width: '100%' }} placeholder="HTTP" />
        </Form.Item>
        <Form.Item name="maxRequests" label="最大请求数 (http2MaxRequests)">
          <InputNumber min={1} max={100000} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="maxRetries" label="最大重试 (maxRetries)">
          <InputNumber min={0} max={100} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="connectTimeoutMs" label="连接超时 (ms)">
          <InputNumber min={1} max={300000} style={{ width: '100%' }} placeholder="connectTimeout" />
        </Form.Item>
        <Form.Item name="maxRequestsPerConnection" label="每连接最大请求数">
          <InputNumber min={1} max={1000} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<ThunderboltOutlined />} loading={loading}>
              应用
            </Button>
            <Button onClick={() => form.resetFields()}>重置</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
