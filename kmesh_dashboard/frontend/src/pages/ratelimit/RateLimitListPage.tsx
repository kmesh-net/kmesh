import { useEffect, useState } from 'react'
import { Card, Table, Button, Spin, Alert, Input } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'
import { getRateLimitList, deleteRateLimit } from '@/api/ratelimit'
import type { RateLimitItem } from '@/types/ratelimit'

export default function RateLimitListPage() {
  const { can } = useAuth()
  const canDelete = can('ratelimit', 'delete')
  const [list, setList] = useState<RateLimitItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nsFilter, setNsFilter] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getRateLimitList(nsFilter || undefined)
      setList(res.items)
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取列表失败')
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
      setError(e instanceof Error ? e.message : '删除失败')
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [nsFilter])

  return (
    <Card
      title="限流策略列表"
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          刷新
        </Button>
      }
    >
      <div style={{ marginBottom: 16 }}>
        <Input
          placeholder="按命名空间筛选（空=全部）"
          value={nsFilter}
          onChange={(e) => setNsFilter(e.target.value)}
          style={{ width: 220 }}
        />
      </div>
      {error && (
        <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
      )}
      <Spin spinning={loading}>
        <Table
          rowKey={(r) => `${r.namespace}/${r.name}`}
          columns={[
            { title: '命名空间', dataIndex: 'namespace', key: 'namespace', width: 120 },
            { title: '名称', dataIndex: 'name', key: 'name', width: 180 },
            { title: 'StatPrefix', dataIndex: 'statPrefix', key: 'statPrefix', width: 140 },
            { title: '最大令牌', dataIndex: 'maxTokens', key: 'maxTokens', width: 90 },
            { title: '每次填充', dataIndex: 'tokensPerFill', key: 'tokensPerFill', width: 90 },
            { title: '填充间隔(秒)', dataIndex: 'fillIntervalSec', key: 'fillIntervalSec', width: 110 },
            {
              title: '作用对象',
              key: 'selector',
              render: (_: unknown, r: RateLimitItem) =>
                r.workloadSelector && Object.keys(r.workloadSelector).length > 0
                  ? JSON.stringify(r.workloadSelector)
                  : '全部',
            },
            ...(canDelete
              ? [
                  {
                    title: '操作',
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
