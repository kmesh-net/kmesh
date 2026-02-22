import { useState } from 'react'
import { Card, Form, Input, Select, Button, Switch, Alert, Space } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import { applyWaypoint } from '@/api/waypoint'

const trafficOptions = [
  { value: '', label: '默认（由控制面决定）' },
  { value: 'service', label: 'Service' },
  { value: 'workload', label: 'Workload' },
  { value: 'all', label: 'All' },
  { value: 'none', label: 'None' },
]

export default function WaypointApplyPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [form] = Form.useForm()

  const onFinish = async (values: Record<string, unknown>) => {
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const res = await applyWaypoint({
        namespace: (values.namespace as string) || 'default',
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
      setError(e instanceof Error ? e.message : '安装失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card title="安装 Waypoint">
      <p style={{ color: '#666', marginBottom: 16 }}>
        按命名空间或指定流量类型（Namespace / Service / Workload）创建 Waypoint。创建后可在「Waypoint 列表」中查看状态。
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
          name: 'waypoint',
          trafficFor: '',
          enrollNamespace: false,
          overwrite: false,
          waitReady: false,
        }}
      >
        <Form.Item name="namespace" label="命名空间" rules={[{ required: true }]}>
          <Input placeholder="default" />
        </Form.Item>
        <Form.Item name="name" label="Waypoint 名称" rules={[{ required: true }]}>
          <Input placeholder="waypoint（Workload 粒度时可填如 reviews-v2-pod-waypoint）" />
        </Form.Item>
        <Form.Item name="trafficFor" label="流量类型">
          <Select options={trafficOptions} placeholder="可选：service / workload / all / none" />
        </Form.Item>
        <Form.Item name="enrollNamespace" label="为命名空间打标签" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="overwrite" label="覆盖已有 Waypoint" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="waitReady" label="等待就绪" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="revision" label="Revision">
          <Input placeholder="可选" />
        </Form.Item>
        <Form.Item name="proxyImage" label="Proxy 镜像">
          <Input placeholder="可选，默认 ghcr.io/kmesh-net/waypoint:latest" />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" icon={<PlusOutlined />} loading={loading}>
              安装
            </Button>
            <Button onClick={() => form.resetFields()}>重置</Button>
          </Space>
        </Form.Item>
      </Form>
    </Card>
  )
}
