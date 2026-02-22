import { useEffect, useState } from 'react'
import { Card, Table, Tag, Spin, Alert, Button, Space, Input, Checkbox } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'
import { getWaypointList, getWaypointStatus, deleteWaypoint } from '@/api/waypoint'
import type { WaypointItem, WaypointStatusItem } from '@/types/waypoint'

const columns = [
  { title: '命名空间', dataIndex: 'namespace', key: 'namespace', width: 140 },
  { title: '名称', dataIndex: 'name', key: 'name', width: 160 },
  {
    title: '状态',
    dataIndex: 'programmed',
    key: 'programmed',
    width: 100,
    render: (v: string) => (
      <Tag color={v === 'True' ? 'green' : v === 'False' ? 'orange' : 'default'}>
        {v === 'True' ? '已就绪' : v === 'False' ? '未就绪' : v}
      </Tag>
    ),
  },
  { title: 'Revision', dataIndex: 'revision', key: 'revision', width: 100 },
  { title: '流量类型', dataIndex: 'trafficFor', key: 'trafficFor', ellipsis: true },
]

export default function WaypointListPage() {
  const { can } = useAuth()
  const [list, setList] = useState<WaypointItem[]>([])
  const [statusMap, setStatusMap] = useState<Record<string, WaypointStatusItem>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nsFilter, setNsFilter] = useState('')
  const [allNamespaces, setAllNamespaces] = useState(true)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [expandedNsFetched, setExpandedNsFetched] = useState<Set<string>>(new Set())
  const canDelete = can('waypoint', 'delete')

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getWaypointList({
        namespace: nsFilter || undefined,
        allNamespaces: allNamespaces || !nsFilter,
      })
      setList(res.items)
      if (res.items.length > 0 && !allNamespaces && nsFilter) {
        const statusRes = await getWaypointStatus(nsFilter)
        const map: Record<string, WaypointStatusItem> = {}
        statusRes.items.forEach((s) => {
          map[`${s.namespace}/${s.name}`] = s
        })
        setStatusMap(map)
      } else {
        setStatusMap({})
      }
      setExpandedNsFetched(new Set())
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (namespace: string, name: string) => {
    setDeleting(`${namespace}/${name}`)
    try {
      await deleteWaypoint({ namespace, names: [name] })
      await fetchList()
    } catch (e) {
      setError(e instanceof Error ? e.message : '删除失败')
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [nsFilter, allNamespaces])

  return (
    <Card
      title="Waypoint 列表与状态"
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          刷新
        </Button>
      }
    >
      <Space style={{ marginBottom: 16 }}>
        <Checkbox
          checked={allNamespaces}
          onChange={(e) => setAllNamespaces(e.target.checked)}
        >
          全部命名空间
        </Checkbox>
        {!allNamespaces && (
          <Input
            placeholder="命名空间"
            value={nsFilter}
            onChange={(e) => setNsFilter(e.target.value)}
            style={{ width: 160 }}
          />
        )}
      </Space>
      {error && (
        <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
      )}
      <Spin spinning={loading}>
        <Table
          rowKey={(r) => `${r.namespace}/${r.name}`}
          columns={[
            ...columns,
            ...(canDelete
              ? [
                  {
                    title: '操作',
                    key: 'action',
                    width: 100,
                    render: (_: unknown, r: WaypointItem) => (
                      <Button
                        type="link"
                        danger
                        size="small"
                        icon={<DeleteOutlined />}
                        loading={deleting === `${r.namespace}/${r.name}`}
                        onClick={() => handleDelete(r.namespace, r.name)}
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
          expandable={{
            onExpand: async (expanded, r) => {
              if (!expanded || expandedNsFetched.has(r.namespace)) return
              setExpandedNsFetched((prev) => new Set(prev).add(r.namespace))
              try {
                const statusRes = await getWaypointStatus(r.namespace)
                setStatusMap((prev) => {
                  const next = { ...prev }
                  statusRes.items.forEach((s) => {
                    next[`${s.namespace}/${s.name}`] = s
                  })
                  return next
                })
              } catch {
                // ignore
              }
            },
            expandedRowRender: (r) => {
              const status = statusMap[`${r.namespace}/${r.name}`]
              if (!status?.conditions?.length)
                return <span style={{ color: '#999' }}>无状态详情或加载中</span>
              return (
                <Table
                  size="small"
                  dataSource={status.conditions}
                  columns={[
                    { title: 'Type', dataIndex: 'type', key: 'type' },
                    { title: 'Status', dataIndex: 'status', key: 'status' },
                    { title: 'Reason', dataIndex: 'reason', key: 'reason' },
                    { title: 'Message', dataIndex: 'message', key: 'message', ellipsis: true },
                  ]}
                  pagination={false}
                />
              )
            },
          }}
        />
      </Spin>
    </Card>
  )
}
