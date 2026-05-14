import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Table, Button, Spin, Alert } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { getCircuitBreakerList, deleteCircuitBreaker } from '@/api/circuitbreaker'
import type { CircuitBreakerItem } from '@/types/circuitbreaker'

const getColumns = (t: (key: string) => string, showNamespace: boolean) => [
  ...(showNamespace ? [{ title: t('waypoint.namespace'), dataIndex: 'namespace', key: 'namespace', width: 140 }] : []),
  { title: t('common.name'), dataIndex: 'name', key: 'name', width: 160 },
  { title: t('circuitbreaker.host'), dataIndex: 'host', key: 'host', ellipsis: true },
  { title: t('circuitbreaker.maxConnections'), dataIndex: 'maxConnections', key: 'maxConnections', width: 100, render: (v: number) => v ?? '-' },
  { title: t('circuitbreaker.maxPendingRequests'), dataIndex: 'maxPendingRequests', key: 'maxPendingRequests', width: 120, render: (v: number) => v ?? '-' },
  { title: t('circuitbreaker.maxRequests'), dataIndex: 'maxRequests', key: 'maxRequests', width: 100, render: (v: number) => v ?? '-' },
  { title: t('circuitbreaker.maxRetries'), dataIndex: 'maxRetries', key: 'maxRetries', width: 90, render: (v: number) => v ?? '-' },
  { title: t('circuitbreaker.connectTimeout'), dataIndex: 'connectTimeoutMs', key: 'connectTimeoutMs', width: 110, render: (v: number) => v ?? '-' },
]

interface CircuitBreakerListPageProps {
  selectedNamespace: string
  allNamespaces?: boolean
}

export default function CircuitBreakerListPage({ selectedNamespace, allNamespaces = false }: CircuitBreakerListPageProps) {
  const { t } = useTranslation()
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
      setError(e instanceof Error ? e.message : t('circuitbreaker.fetchFailed'))
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
      setError(e instanceof Error ? e.message : t('circuitbreaker.deleteFailed'))
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [selectedNamespace, allNamespaces])

  return (
    <Card
      title={t('circuitbreaker.listTitle')}
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          {t('common.refresh')}
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
            ...getColumns(t, allNamespaces),
            {
              title: t('common.operation'),
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
                  {t('common.delete')}
                </Button>
              ),
            },
          ]}
          dataSource={list}
          pagination={{ pageSize: 10, showSizeChanger: true }}
        />
      </Spin>
    </Card>
  )
}
