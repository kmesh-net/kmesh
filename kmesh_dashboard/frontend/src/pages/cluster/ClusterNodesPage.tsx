import { useEffect, useState } from 'react'
import { Card, Table, Tag, Spin, Alert, Button } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'
import { getClusterNodes } from '@/api/cluster'
import type { NodeItem } from '@/types/cluster'

export default function ClusterNodesPage() {
  const { t } = useTranslation()
  const [nodes, setNodes] = useState<NodeItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const columns = [
    { title: t('cluster.nodeName'), dataIndex: 'name', key: 'name', ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'status',
      key: 'status',
      render: (s: string) => (
        <Tag color={s === 'Ready' ? 'green' : 'orange'}>{s}</Tag>
      ),
    },
    {
      title: t('cluster.roles'),
      dataIndex: 'roles',
      key: 'roles',
      render: (roles: string[]) => roles?.join(', ') ?? '-',
    },
    { title: t('cluster.internalIP'), dataIndex: 'internalIP', key: 'internalIP' },
    { title: t('cluster.age'), dataIndex: 'age', key: 'age' },
    { title: t('cluster.kernel'), dataIndex: 'kernel', key: 'kernel', ellipsis: true },
    { title: t('cluster.osImage'), dataIndex: 'osImage', key: 'osImage', ellipsis: true },
  ]

  const fetchNodes = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getClusterNodes()
      setNodes(res.nodes)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('cluster.fetchFailed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchNodes()
  }, [])

  return (
    <Card
      title={t('cluster.title')}
      extra={
        <Button
          type="primary"
          icon={<ReloadOutlined />}
          onClick={fetchNodes}
          loading={loading}
        >
          {t('common.refresh')}
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
