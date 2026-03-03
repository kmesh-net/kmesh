import { useEffect, useState } from 'react'
import { Card, Table, Tag, Spin, Alert, Button, Tooltip, Descriptions, Row, Col } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'
import { getWaypointList, getWaypointStatus, deleteWaypoint } from '@/api/waypoint'
import type { WaypointItem, WaypointStatusItem } from '@/types/waypoint'

const getColumns = (
  showNamespace: boolean,
  statusMap: Record<string, WaypointStatusItem>
) => [
  ...(showNamespace ? [{ title: '命名空间', dataIndex: 'namespace', key: 'namespace', width: 140 }] : []),
  { title: '名称', dataIndex: 'name', key: 'name', width: 160 },
  {
    title: '状态',
    dataIndex: 'programmed',
    key: 'programmed',
    width: 160,
    render: (v: string, r: WaypointItem) => {
      const gwReady = v === 'True'
      const status = statusMap[`${r.namespace}/${r.name}`]
      const ps = status?.podStatus
      const bothReady = gwReady && ps && ps.ready === ps.total && ps.phase === 'Running'
      const shortPod = !ps ? '' : ps.total === 0 ? '待部署' : `${ps.ready}/${ps.total}`
      const fullPod = ps?.message ?? ''
      const tagContent = (
        <Tag color={bothReady ? 'green' : gwReady ? 'blue' : ps?.phase === 'Failed' ? 'red' : 'orange'}>
          {bothReady ? '已就绪' : gwReady ? 'Gateway 就绪' : '未就绪'}
          {shortPod ? ` (${shortPod})` : ''}
        </Tag>
      )
      return fullPod && fullPod !== shortPod ? (
        <Tooltip title={fullPod}>{tagContent}</Tooltip>
      ) : (
        tagContent
      )
    },
  },
  { title: 'Revision', dataIndex: 'revision', key: 'revision', width: 100 },
  { title: '流量类型', dataIndex: 'trafficFor', key: 'trafficFor', ellipsis: true },
]

interface WaypointListPageProps {
  selectedNamespace: string
  allNamespaces: boolean
}

export default function WaypointListPage({ selectedNamespace, allNamespaces }: WaypointListPageProps) {
  const { can } = useAuth()
  const [list, setList] = useState<WaypointItem[]>([])
  const [statusMap, setStatusMap] = useState<Record<string, WaypointStatusItem>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [expandedNsFetched, setExpandedNsFetched] = useState<Set<string>>(new Set())
  const canDelete = can('waypoint', 'delete')

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getWaypointList({
        namespace: allNamespaces ? undefined : selectedNamespace,
        allNamespaces,
      })
      setList(res.items)
      if (res.items.length > 0) {
        const namespacesToFetch = allNamespaces
          ? [...new Set(res.items.map((i) => i.namespace))]
          : selectedNamespace
            ? [selectedNamespace]
            : []
        const map: Record<string, WaypointStatusItem> = {}
        await Promise.all(
          namespacesToFetch.map(async (ns) => {
            try {
              const statusRes = await getWaypointStatus(ns)
              statusRes.items.forEach((s) => {
                map[`${s.namespace}/${s.name}`] = s
              })
            } catch {
              // 单个 ns 失败不阻断
            }
          })
        )
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
  }, [selectedNamespace, allNamespaces])

  return (
    <Card
      title="Waypoint 列表与状态"
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
            ...getColumns(allNamespaces, statusMap),
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
              if (!status) return <span style={{ color: '#999' }}>加载中</span>
              const { conditions, podStatus } = status
              const phaseColor: Record<string, string> = {
                Running: 'success',
                Pending: 'warning',
                Failed: 'error',
                Unknown: 'default',
              }
              return (
                <div
                  style={{
                    marginLeft: 8,
                    padding: '14px 20px',
                    background: 'linear-gradient(90deg, rgba(22,119,255,.08) 0%, rgba(22,119,255,.02) 12px, transparent 40px)',
                    borderLeft: '3px solid #1677ff',
                    borderRadius: '0 6px 6px 0',
                    boxShadow: 'inset 0 1px 0 0 rgba(255,255,255,.5)',
                  }}
                >
                  <div
                    style={{
                      fontSize: 12,
                      color: '#1677ff',
                      marginBottom: 12,
                      fontWeight: 500,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    <span>↳</span>
                    <span>{r.namespace} / {r.name}</span>
                    <span style={{ color: '#999', fontWeight: 400 }}>— 状态详情</span>
                  </div>
                  <Row gutter={24}>
                    {podStatus && (
                      <Col span={conditions?.length ? 12 : 24}>
                        <div style={{ marginBottom: conditions?.length ? 0 : 12 }}>
                          <div style={{ fontSize: 13, color: '#666', marginBottom: 8 }}>Waypoint Pod</div>
                          <Descriptions column={1} size="small">
                            <Descriptions.Item label="概要">{podStatus.message}</Descriptions.Item>
                          </Descriptions>
                          {podStatus.pods?.length ? (
                            <Table
                              size="small"
                              dataSource={podStatus.pods}
                              columns={[
                                { title: 'Pod', dataIndex: 'name', key: 'name', ellipsis: true },
                                {
                                  title: 'Phase',
                                  dataIndex: 'phase',
                                  key: 'phase',
                                  width: 90,
                                  render: (phase: string) => (
                                    <Tag color={phaseColor[phase] ?? 'default'}>{phase}</Tag>
                                  ),
                                },
                                {
                                  title: 'Ready',
                                  dataIndex: 'ready',
                                  key: 'ready',
                                  width: 70,
                                  render: (v: boolean) => (
                                    <Tag color={v ? 'success' : 'default'}>{v ? '是' : '否'}</Tag>
                                  ),
                                },
                                {
                                  title: 'Reason',
                                  dataIndex: 'reason',
                                  key: 'reason',
                                  ellipsis: true,
                                  render: (reason: string) =>
                                    reason ? (
                                      <Tooltip title={reason} overlayInnerStyle={{ maxWidth: 480, wordBreak: 'break-word' }}>
                                        <span style={{ cursor: 'default' }}>{reason}</span>
                                      </Tooltip>
                                    ) : (
                                      '-'
                                    ),
                                },
                              ]}
                              pagination={false}
                              style={{ marginTop: 8 }}
                            />
                          ) : null}
                        </div>
                      </Col>
                    )}
                    {conditions?.length ? (
                      <Col span={podStatus ? 12 : 24}>
                        <div>
                          <div style={{ fontSize: 13, color: '#666', marginBottom: 8 }}>Gateway Conditions</div>
                          <Table
                            size="small"
                            dataSource={conditions}
                            columns={[
                              { title: 'Type', dataIndex: 'type', key: 'type', width: 140 },
                              {
                                title: 'Status',
                                dataIndex: 'status',
                                key: 'status',
                                width: 80,
                                render: (s: string) => (
                                  <Tag color={s === 'True' ? 'success' : s === 'False' ? 'warning' : 'default'}>
                                    {s}
                                  </Tag>
                                ),
                              },
                              { title: 'Reason', dataIndex: 'reason', key: 'reason', width: 100 },
                              {
                                title: 'Message',
                                dataIndex: 'message',
                                key: 'message',
                                ellipsis: true,
                                render: (msg: string) =>
                                  msg ? (
                                    <Tooltip title={msg} overlayInnerStyle={{ maxWidth: 480, wordBreak: 'break-word' }}>
                                      <span style={{ cursor: 'default' }}>{msg}</span>
                                    </Tooltip>
                                  ) : (
                                    '-'
                                  ),
                              },
                            ]}
                            pagination={false}
                          />
                        </div>
                      </Col>
                    ) : !podStatus ? (
                      <Col span={24}>
                        <span style={{ color: '#999' }}>无状态详情</span>
                      </Col>
                    ) : null}
                  </Row>
                </div>
              )
            },
          }}
        />
      </Spin>
    </Card>
  )
}
