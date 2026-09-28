import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Form, Input, Select, Button, Alert, Space } from 'antd'
import { SafetyOutlined, PlusOutlined, DeleteOutlined } from '@ant-design/icons'
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

function formRuleToApiRule(r: { ipBlocks?: string; namespaces?: string; ports?: string; hosts?: string; paths?: string; methods?: string }): AuthorizationPolicyRuleApply | null {
  const ipBlocks = parseCommaList(r.ipBlocks)
  const namespaces = parseCommaList(r.namespaces)
  const ports = parseCommaList(r.ports)
  const hosts = parseCommaList(r.hosts)
  const paths = parseCommaList(r.paths)
  const methods = parseCommaList(r.methods)
  const hasFrom = ipBlocks.length > 0 || namespaces.length > 0
  const hasTo = ports.length > 0 || hosts.length > 0 || paths.length > 0 || methods.length > 0
  if (!hasFrom && !hasTo) return null
  const rule: AuthorizationPolicyRuleApply = {}
  if (hasFrom) {
    rule.from = [{ source: {} }]
    if (ipBlocks.length > 0) rule.from![0].source!.ipBlocks = ipBlocks
    if (namespaces.length > 0) rule.from![0].source!.namespaces = namespaces
  }
  if (hasTo) {
    rule.to = [{ operation: {} }]
    if (ports.length > 0) rule.to![0].operation!.ports = ports
    if (hosts.length > 0) rule.to![0].operation!.hosts = hosts
    if (paths.length > 0) rule.to![0].operation!.paths = paths
    if (methods.length > 0) rule.to![0].operation!.methods = methods
  }
  return rule
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
      const rulesRaw = (values.rules as Array<Record<string, string>>) || []
      const rules: AuthorizationPolicyRuleApply[] = []
      for (const r of rulesRaw) {
        const apiRule = formRuleToApiRule(r)
        if (apiRule) rules.push(apiRule)
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
          rules: [{}],
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

        <Form.List name="rules" initialValue={[{}]}>
          {(fields, { add, remove }) => (
            <>
              <div style={{ marginTop: 24, marginBottom: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontWeight: 500 }}>{t('authorization.rulesConfig')}</span>
                <Button type="dashed" onClick={() => add({})} icon={<PlusOutlined />}>
                  {t('authorization.addRule')}
                </Button>
              </div>
              <div style={{ marginBottom: 12, fontSize: 12, color: '#888' }}>{t('authorization.rulesHint')}</div>
              {fields.map(({ key, name }) => (
                <div
                  key={key}
                  style={{
                    marginBottom: 16,
                    padding: 16,
                    border: '1px solid #d9d9d9',
                    borderRadius: 8,
                    background: '#fafafa',
                    position: 'relative',
                  }}
                >
                  <div style={{ marginBottom: 12, fontWeight: 500 }}>
                    {t('authorization.rule')} #{name + 1}
                    {fields.length > 1 && (
                      <Button
                        type="text"
                        danger
                        size="small"
                        icon={<DeleteOutlined />}
                        onClick={() => remove(name)}
                        style={{ marginLeft: 8 }}
                      >
                        {t('common.delete')}
                      </Button>
                    )}
                  </div>
                  <div style={{ marginBottom: 8, fontSize: 13, color: '#666' }}>{t('authorization.fromConditions')}</div>
                  <Form.Item name={[name, 'ipBlocks']} label={t('authorization.sourceIpBlocks')} style={{ marginBottom: 12 }}>
                    <Input placeholder="10.0.0.0/8, 192.168.1.0/24" />
                  </Form.Item>
                  <Form.Item name={[name, 'namespaces']} label={t('authorization.sourceNamespaces')} style={{ marginBottom: 12 }}>
                    <Input placeholder="foo, bar" />
                  </Form.Item>
                  <div style={{ marginBottom: 8, fontSize: 13, color: '#666' }}>{t('authorization.toConditions')}</div>
                  <Form.Item name={[name, 'ports']} label={t('authorization.targetPorts')} style={{ marginBottom: 12 }}>
                    <Input placeholder="9090, 8080" />
                  </Form.Item>
                  <Form.Item name={[name, 'hosts']} label={t('authorization.targetHosts')} style={{ marginBottom: 12 }}>
                    <Input placeholder="*.example.com" />
                  </Form.Item>
                  <Form.Item name={[name, 'paths']} label={t('authorization.targetPaths')} style={{ marginBottom: 12 }}>
                    <Input placeholder="/api, /admin" />
                  </Form.Item>
                  <Form.Item name={[name, 'methods']} label={t('authorization.httpMethods')}>
                    <Input placeholder="GET, POST" />
                  </Form.Item>
                </div>
              ))}
            </>
          )}
        </Form.List>

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
