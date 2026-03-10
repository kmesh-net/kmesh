import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
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
  const { t } = useTranslation()
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
      setError(e instanceof Error ? e.message : t('ratelimit.applyFailed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title={t('ratelimit.config')}>
      <p style={{ color: '#666', marginBottom: 16 }}>
        {t('ratelimit.formDesc')}
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
        <Form.Item name="name" label={t('ratelimit.filterName')} rules={[{ required: true }]}>
          <Input placeholder={t('ratelimit.filterNamePlaceholder')} />
        </Form.Item>
        <Form.Item name="statPrefix" label={t('ratelimit.statPrefix')}>
          <Input placeholder={t('ratelimit.statPlaceholder')} />
        </Form.Item>
        <Form.Item
          name="selectorApp"
          label={t('ratelimit.selectorLabel')}
          extra={t('ratelimit.selectorExtra')}
        >
          <Select
            allowClear
            placeholder={t('ratelimit.noLimitPlaceholder')}
            options={[
              { value: '', label: t('ratelimit.selectorAllOption') },
              ...services.map((s) => ({ value: s.name, label: s.name })),
            ]}
          />
        </Form.Item>
        <Form.Item name="maxTokens" label={t('ratelimit.maxTokensLabel')} rules={[{ required: true }]}>
          <InputNumber min={1} max={100000} placeholder="4" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="tokensPerFill" label={t('ratelimit.tokensPerFillLabel')} rules={[{ required: true }]}>
          <InputNumber min={1} max={100000} placeholder="4" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="fillIntervalSec" label={t('ratelimit.fillIntervalLabel')} rules={[{ required: true }]}>
          <InputNumber min={1} max={86400} placeholder="60" style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<FilterOutlined />} loading={loading}>
              {t('ratelimit.submitBtn')}
            </Button>
            <Button onClick={() => form.resetFields()}>{t('common.reset')}</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
