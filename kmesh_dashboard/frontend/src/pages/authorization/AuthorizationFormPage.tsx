import { useState } from 'react'
import { Card, Form, Input, Select, Button, Alert, Space } from 'antd'
import { SafetyOutlined } from '@ant-design/icons'
import { applyAuthorizationPolicy } from '@/api/authorization'
import type {
  AuthorizationPolicyApplyRequest,
  AuthorizationPolicyRuleApply,
} from '@/types/authorization'

function parseCommaList(s: string | undefined): string[] {
  if (!s || !s.trim()) return []
  return s
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

export default function AuthorizationFormPage() {
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
        namespace: (values.namespace as string) || 'default',
        name: values.name as string,
        action: (values.action as 'ALLOW' | 'DENY') || 'ALLOW',
      }
      if (Object.keys(selector).length > 0) req.selector = selector
      if (rules.length > 0) req.rules = rules

      const res = await applyAuthorizationPolicy(req)
      setSuccess(res.message)
      form.resetFields()
    } catch (e) {
      setError(e instanceof Error ? e.message : '应用失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="配置授权策略">
      <p style={{ color: '#666', marginBottom: 16 }}>
        创建或更新 Istio AuthorizationPolicy，限制哪些来源可访问目标工作负载。Kmesh 支持 L4 层条件：IP 段、命名空间、端口等。
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
          namespace: 'default',
          action: 'ALLOW',
        }}
      >
        <Form.Item name="namespace" label="命名空间" rules={[{ required: true }]}>
          <Input placeholder="default" />
        </Form.Item>
        <Form.Item name="name" label="策略名称" rules={[{ required: true }]}>
          <Input placeholder="例如 ip-allow-policy" />
        </Form.Item>
        <Form.Item name="action" label="动作" rules={[{ required: true }]}>
          <Select
            options={[
              { value: 'ALLOW', label: 'ALLOW - 允许匹配规则的请求' },
              { value: 'DENY', label: 'DENY - 拒绝匹配规则的请求' },
            ]}
          />
        </Form.Item>
        <Form.Item
          name="selectorApp"
          label="目标工作负载 (app 标签)"
          extra="策略将作用于带该 app 标签的 Pod"
        >
          <Input placeholder="例如 httpbin、reviews" />
        </Form.Item>

        <div style={{ marginTop: 24, marginBottom: 8, fontWeight: 500 }}>来源条件 (from)</div>
        <Form.Item
          name="ipBlocks"
          label="来源 IP 段"
          extra="逗号分隔，如 10.0.0.0/8, 192.168.1.0/24"
        >
          <Input placeholder="10.0.0.0/8, 192.168.1.0/24" />
        </Form.Item>
        <Form.Item
          name="namespaces"
          label="来源命名空间"
          extra="逗号分隔，仅允许来自这些命名空间的请求"
        >
          <Input placeholder="foo, bar" />
        </Form.Item>

        <div style={{ marginTop: 24, marginBottom: 8, fontWeight: 500 }}>目标操作 (to)</div>
        <Form.Item name="ports" label="目标端口" extra="逗号分隔，如 9090, 8080">
          <Input placeholder="9090, 8080" />
        </Form.Item>
        <Form.Item name="hosts" label="目标 Host" extra="逗号分隔">
          <Input placeholder="*.example.com" />
        </Form.Item>
        <Form.Item name="paths" label="目标路径" extra="逗号分隔，如 /api, /admin">
          <Input placeholder="/api, /admin" />
        </Form.Item>
        <Form.Item name="methods" label="HTTP 方法" extra="逗号分隔，如 GET, POST">
          <Input placeholder="GET, POST" />
        </Form.Item>

        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<SafetyOutlined />} loading={loading}>
              应用
            </Button>
            <Button onClick={() => form.resetFields()}>重置</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
