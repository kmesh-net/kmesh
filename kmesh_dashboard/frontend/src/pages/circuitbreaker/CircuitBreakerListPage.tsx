import { useEffect, useState } from 'react'
import { Card, Table, Button, Spin, Alert } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'
import { getCircuitBreakerList, deleteCircuitBreaker } from '@/api/circuitbreaker'
import type { CircuitBreakerItem } from '@/types/circuitbreaker'

const getColumns = (showNamespace: boolean) => [
  ...(showNamespace ? [{ title: '命名空间', dataIndex: 'namespace', key: 'namespace', width: 140 }] : []),
  { title: '名称', dataIndex: 'name', key: 'name', width: 160 },
  { title: '目标 Host', dataIndex: 'host', key: 'host', ellipsis: true },
  { title: '最大连接数', dataIndex: 'maxConnections', key: 'maxConnections', width: 100, render: (v: number) => v ?? '-' },
  { title: '最大待处理请求', dataIndex: 'maxPendingRequests', key: 'maxPendingRequests', width: 120, render: (v: number) => v ?? '-' },
  { title: '最大请求数', dataIndex: 'maxRequests', key: 'maxRequests', width: 100, render: (v: number) => v ?? '-' },
  { title: '最大重试', dataIndex: 'maxRetries', key: 'maxRetries', width: 90, render: (v: number) => v ?? '-' },
  { title: '连接超时(ms)', dataIndex: 'connectTimeoutMs', key: 'connectTimeoutMs', width: 110, render: (v: number) => v ?? '-' },
]

interface CircuitBreakerListPageProps {
  selectedNamespace: string
  allNamespaces?: boolean
}

export default function CircuitBreakerListPage({ selectedNamespace, allNamespaces = false }: CircuitBreakerListPageProps) {
  const { can } = useAuth()
  const canDelete = can('circuitbreaker', 'delete')
  const [list, setList] = useState<CircuitBreakerItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getCircuitBreakerList(allNamespaces ? undefined : selectedNamespace || undefined)
      setList(res.items)
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (item: CircuitBreakerItem) => {
    const key = `${item.namespace}/${item.name}`
    setDeleting(key)
    try {
      await deleteCircuitBreaker({ namespace: item.namespace, name: item.name })
      await fetchList()
    } catch (e) {
      setError(e instanceof Error ? e.message : '删除失败')
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [selectedNamespace, allNamespaces])

  return (
    <Card
      title="熔断策略列表"
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          刷新
        </Button>
      }
    >
      {error && (
        <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
      )}
      <Spin spinning={loading}>
        <Table
          rowKey={(r) => `${r.namespace}/${r.name}`}
          columns={[
            ...getColumns(allNamespaces),
            ...(canDelete
              ? [
                  {
                    title: '操作',
                    key: 'action',
                    width: 90,
                    render: (_: unknown, r: CircuitBreakerItem) => (
                      <Button
                        type="link"
                        danger
                        size="small"
                        icon={<DeleteOutlined />}
                        loading={deleting === `${r.namespace}/${r.name}`}
                        onClick={() => handleDelete(r)}
                      >
                        删除
                      </Button>
                    ),
                  },
                ]
              : []),
          ]}
          dataSource={list}
          pagination={{ pageSize: 10, showSizeChanger: true }}
        />
      </Spin>
    </Card>
  )
}
