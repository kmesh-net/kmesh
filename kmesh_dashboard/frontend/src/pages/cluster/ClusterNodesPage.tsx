import { useEffect, useState } from 'react'
import { Card, Table, Tag, Spin, Alert, Button } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { getClusterNodes } from '@/api/cluster'
import type { NodeItem } from '@/types/cluster'

const columns = [
  { title: '节点名称', dataIndex: 'name', key: 'name', ellipsis: true },
  {
    title: '状态',
    dataIndex: 'status',
    key: 'status',
    render: (s: string) => (
      <Tag color={s === 'Ready' ? 'green' : 'orange'}>{s}</Tag>
    ),
  },
  {
    title: '角色',
    dataIndex: 'roles',
    key: 'roles',
    render: (roles: string[]) => roles?.join(', ') ?? '-',
  },
  { title: '内网 IP', dataIndex: 'internalIP', key: 'internalIP' },
  { title: '运行时长', dataIndex: 'age', key: 'age' },
  { title: '内核', dataIndex: 'kernel', key: 'kernel', ellipsis: true },
  { title: 'OS 镜像', dataIndex: 'osImage', key: 'osImage', ellipsis: true },
]

export default function ClusterNodesPage() {
  const [nodes, setNodes] = useState<NodeItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchNodes = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getClusterNodes()
      setNodes(res.nodes)
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取节点列表失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchNodes()
  }, [])

  return (
    <Card
      title="集群节点"
      extra={
        <Button
          type="primary"
          icon={<ReloadOutlined />}
          onClick={fetchNodes}
          loading={loading}
        >
          刷新
        </Button>
      }
    >
      {error && (
        <Alert
          type="error"
          message={error}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}
      <Spin spinning={loading}>
        <Table
          rowKey="name"
          columns={columns}
          dataSource={nodes}
          pagination={{ pageSize: 10, showSizeChanger: true }}
        />
      </Spin>
    </Card>
  )
}
