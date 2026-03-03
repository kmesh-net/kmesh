import { useState, useEffect } from 'react'
import { Card, Form, Input, InputNumber, Button, Alert, Space, Select } from 'antd'
import { FilterOutlined } from '@ant-design/icons'
import { applyRateLimit } from '@/api/ratelimit'
import { getServiceList } from '@/api/services'
import type { ServiceItem } from '@/api/services'
import type { RateLimitApplyRequest } from '@/types/ratelimit'

interface RateLimitFormPageProps {
  selectedNamespace: string
  namespaceOptions: string[]
}

export default function RateLimitFormPage({ selectedNamespace }: RateLimitFormPageProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [services, setServices] = useState<ServiceItem[]>([])
  const [form] = Form.useForm<RateLimitApplyRequest & { selectorApp?: string }>()

  useEffect(() => {
    getServiceList(selectedNamespace || undefined)
      .then((res) => setServices(res.items))
      .catch(() => setServices([]))
  }, [selectedNamespace])

  const onFinish = async (values: RateLimitApplyRequest & { selectorApp?: string }) => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const req: RateLimitApplyRequest = {
        namespace: selectedNamespace || 'default',
        name: values.name,
        maxTokens: values.maxTokens!,
        tokensPerFill: values.tokensPerFill!,
        fillIntervalSec: values.fillIntervalSec!,
      }
      if (values.statPrefix) req.statPrefix = values.statPrefix
      if (values.selectorApp) {
        req.workloadSelector = { app: values.selectorApp }
      }
      const res = await applyRateLimit(req)
      setSuccess(res.message)
      form.resetFields()
    } catch (e) {
      setError(e instanceof Error ? e.message : '下发失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="配置限流">
      <p style={{ color: '#666', marginBottom: 16 }}>
        在<strong>当前命名空间</strong>（上方选择器）下按 Token Bucket 配置连接维度限流（每 fill_interval 补充 tokens_per_fill，最多 max_tokens）。通过 EnvoyFilter 插入 <code>envoy.filters.network.local_ratelimit</code>，需集群已安装 Istio EnvoyFilter CRD。
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
        <Form.Item name="name" label="EnvoyFilter 名称" rules={[{ required: true }]}>
          <Input placeholder="例如 filter-local-ratelimit-svc" />
        </Form.Item>
        <Form.Item name="statPrefix" label="Stat 前缀">
          <Input placeholder="可选，默认 local_rate_limit" />
        </Form.Item>
        <Form.Item
          name="selectorApp"
          label="作用对象（按 workload 的 app 标签）"
          extra="可选。从当前命名空间的服务中选一个，将用其名称作为 app 标签仅对该 workload 限流；不选则对该命名空间下所有匹配的 listener 生效。"
        >
          <Select
            allowClear
            placeholder="不限定（全部）"
            options={[
              { value: '', label: '不限定（全部）' },
              ...services.map((s) => ({ value: s.name, label: s.name })),
            ]}
          />
        </Form.Item>
        <Form.Item name="maxTokens" label="最大令牌数 (max_tokens)" rules={[{ required: true }]}>
          <InputNumber min={1} max={100000} placeholder="如 4" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="tokensPerFill" label="每次填充令牌数 (tokens_per_fill)" rules={[{ required: true }]}>
          <InputNumber min={1} max={100000} placeholder="如 4" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="fillIntervalSec" label="填充间隔（秒）(fill_interval)" rules={[{ required: true }]}>
          <InputNumber min={1} max={86400} placeholder="如 60" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<FilterOutlined />} loading={loading}>
              下发
            </Button>
            <Button onClick={() => form.resetFields()}>重置</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
