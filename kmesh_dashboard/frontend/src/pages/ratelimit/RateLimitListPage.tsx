import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Table, Button, Spin, Alert } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { getRateLimitList, deleteRateLimit } from '@/api/ratelimit'
import type { RateLimitItem } from '@/types/ratelimit'

const getColumns = (t: (key: string) => string, showNamespace: boolean) => [
  ...(showNamespace ? [{ title: t('waypoint.namespace'), dataIndex: 'namespace', key: 'namespace', width: 140 }] : []),
  { title: t('common.name'), dataIndex: 'name', key: 'name', width: 180 },
  { title: t('ratelimit.statPrefix'), dataIndex: 'statPrefix', key: 'statPrefix', width: 140 },
  { title: t('ratelimit.maxTokens'), dataIndex: 'maxTokens', key: 'maxTokens', width: 90 },
  { title: t('ratelimit.tokensPerFill'), dataIndex: 'tokensPerFill', key: 'tokensPerFill', width: 90 },
  { title: t('ratelimit.fillInterval'), dataIndex: 'fillIntervalSec', key: 'fillIntervalSec', width: 110 },
  {
    title: t('ratelimit.selector'),
    key: 'selector',
    render: (_: unknown, r: RateLimitItem) =>
      r.workloadSelector && Object.keys(r.workloadSelector).length > 0
        ? JSON.stringify(r.workloadSelector)
        : t('ratelimit.all'),
  },
]

interface RateLimitListPageProps {
  selectedNamespace: string
  allNamespaces?: boolean
}

export default function RateLimitListPage({ selectedNamespace, allNamespaces = false }: RateLimitListPageProps) {
  const { t } = useTranslation()
  const [list, setList] = useState<RateLimitItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getRateLimitList(allNamespaces ? undefined : selectedNamespace || undefined)
      setList(res.items)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('ratelimit.fetchFailed'))
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (item: RateLimitItem) => {
    const key = `${item.namespace}/${item.name}`
    setDeleting(key)
    try {
      await deleteRateLimit({ namespace: item.namespace, name: item.name })
      await fetchList()
    } catch (e) {
      setError(e instanceof Error ? e.message : t('ratelimit.deleteFailed'))
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [selectedNamespace, allNamespaces])

  return (
    <Card
      title={t('ratelimit.listTitle')}
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
              render: (_: unknown, r: RateLimitItem) => (
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
