import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Form, Input, Select, Button, Alert, Space } from 'antd'
import { SafetyOutlined } from '@ant-design/icons'
import { applyAuthorizationPolicy } from '@/api/authorization'
import type {
  AuthorizationPolicyApplyRequest,
  AuthorizationPolicyRuleApply,
} from '@/types/authorization'

interface AuthorizationFormPageProps {
  selectedNamespace: string
  namespaceOptions: string[]
}

function parseCommaList(s: string | undefined): string[] {
  if (!s || !s.trim()) return []
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

export default function AuthorizationFormPage({ selectedNamespace }: AuthorizationFormPageProps) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [form] = Form.useForm()

  const onFinish = async (values: Record<string, unknown>) => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const rules: AuthorizationPolicyRuleApply[] = []
      const ipBlocks = parseCommaList(values.ipBlocks as string)
      const namespaces = parseCommaList(values.namespaces as string)
      const ports = parseCommaList(values.ports as string)
      const hosts = parseCommaList(values.hosts as string)
      const paths = parseCommaList(values.paths as string)
      const methods = parseCommaList(values.methods as string)

      const hasFrom = ipBlocks.length > 0 || namespaces.length > 0
      const hasTo = ports.length > 0 || hosts.length > 0 || paths.length > 0 || methods.length > 0

      if (hasFrom || hasTo) {
        const rule: AuthorizationPolicyRuleApply = {}
        if (hasFrom) {
          rule.from = [
            {
              source: {},
            },
          ]
          if (ipBlocks.length > 0) rule.from![0].source!.ipBlocks = ipBlocks
          if (namespaces.length > 0) rule.from![0].source!.namespaces = namespaces
        }
        if (hasTo) {
          rule.to = [
            {
              operation: {},
            },
          ]
          if (ports.length > 0) rule.to![0].operation!.ports = ports
          if (hosts.length > 0) rule.to![0].operation!.hosts = hosts
          if (paths.length > 0) rule.to![0].operation!.paths = paths
          if (methods.length > 0) rule.to![0].operation!.methods = methods
        }
        rules.push(rule)
      }

      const selector: Record<string, string> = {}
      const app = (values.selectorApp as string)?.trim()
      if (app) selector.app = app

      const req: AuthorizationPolicyApplyRequest = {
        namespace: selectedNamespace || 'default',
        name: values.name as string,
        action: (values.action as 'ALLOW' | 'DENY') || 'ALLOW',
      }
      if (Object.keys(selector).length > 0) req.selector = selector
      if (rules.length > 0) req.rules = rules

      const res = await applyAuthorizationPolicy(req)
      setSuccess(res.message)
      form.resetFields()
    } catch (e) {
      setError(e instanceof Error ? e.message : t('common.applyFailed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title={t('authorization.config')}>
      <p style={{ color: '#666', marginBottom: 16 }}>
        {t('authorization.formDesc')}
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
          action: 'ALLOW',
        }}
      >
        <Form.Item name="name" label={t('authorization.policyName')} rules={[{ required: true }]}>
          <Input placeholder={t('authorization.policyNamePlaceholder')} />
        </Form.Item>
        <Form.Item name="action" label={t('authorization.actionLabel')} rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'ALLOW', label: t('authorization.allowDesc') },
              { value: 'DENY', label: t('authorization.denyDesc') },
            ]}
          />
        </Form.Item>
        <Form.Item
          name="selectorApp"
          label={t('authorization.targetWorkloadLabel')}
          extra={t('authorization.targetWorkloadExtra')}
        >
          <Input placeholder={t('authorization.targetWorkloadPlaceholder')} />
        </Form.Item>

        <div style={{ marginTop: 24, marginBottom: 8, fontWeight: 500 }}>{t('authorization.fromConditions')}</div>
        <Form.Item
          name="ipBlocks"
          label={t('authorization.sourceIpBlocks')}
          extra={t('authorization.sourceIpBlocksExtra')}
        >
          <Input placeholder="10.0.0.0/8, 192.168.1.0/24" />
        </Form.Item>
        <Form.Item
          name="namespaces"
          label={t('authorization.sourceNamespaces')}
          extra={t('authorization.sourceNamespacesExtra')}
        >
          <Input placeholder="foo, bar" />
        </Form.Item>

        <div style={{ marginTop: 24, marginBottom: 8, fontWeight: 500 }}>{t('authorization.toConditions')}</div>
        <Form.Item name="ports" label={t('authorization.targetPorts')} extra={t('authorization.targetPortsExtra')}>
          <Input placeholder="9090, 8080" />
        </Form.Item>
        <Form.Item name="hosts" label={t('authorization.targetHosts')} extra={t('authorization.targetHostsExtra')}>
          <Input placeholder="*.example.com" />
        </Form.Item>
        <Form.Item name="paths" label={t('authorization.targetPaths')} extra={t('authorization.targetPathsExtra')}>
          <Input placeholder="/api, /admin" />
        </Form.Item>
        <Form.Item name="methods" label={t('authorization.httpMethods')} extra={t('authorization.httpMethodsExtra')}>
          <Input placeholder="GET, POST" />
        </Form.Item>

        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<SafetyOutlined />} loading={loading}>
              {t('common.apply')}
            </Button>
            <Button onClick={() => form.resetFields()}>{t('common.reset')}</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
