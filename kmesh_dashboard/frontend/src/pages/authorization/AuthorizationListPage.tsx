import { useEffect, useState } from 'react'
import { Card, Table, Button, Spin, Alert, Input, Tag } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { useAuth } from '@/contexts/AuthContext'
import { getAuthorizationList, deleteAuthorizationPolicy } from '@/api/authorization'
import type { AuthorizationPolicyItem } from '@/types/authorization'

export default function AuthorizationListPage() {
  const { can } = useAuth()
  const canDelete = can('authorization', 'delete')
  const [list, setList] = useState<AuthorizationPolicyItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nsFilter, setNsFilter] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getAuthorizationList(nsFilter || undefined)
      setList(res.items)
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (item: AuthorizationPolicyItem) => {
    const key = `${item.namespace}/${item.name}`
    setDeleting(key)
    try {
      await deleteAuthorizationPolicy({ namespace: item.namespace, name: item.name })
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

  const renderRuleDetail = (item: AuthorizationPolicyItem) => {
    if (!item.rules || item.rules.length === 0) return '-'
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 360 }}>
        {item.rules.map((rule, idx) => {
          const fromParts: string[] = []
          rule.from?.forEach((f) => {
            if (f.source?.ipBlocks?.length) fromParts.push(`IP: ${f.source.ipBlocks.join(', ')}`)
            if (f.source?.namespaces?.length) fromParts.push(`NS: ${f.source.namespaces.join(', ')}`)
            if (f.source?.principals?.length) fromParts.push(`Principal: ${f.source.principals.join(', ')}`)
          })
          const toParts: string[] = []
          rule.to?.forEach((t) => {
            if (t.operation?.ports?.length) toParts.push(`端口: ${t.operation.ports.join(', ')}`)
            if (t.operation?.hosts?.length) toParts.push(`Host: ${t.operation.hosts.join(', ')}`)
            if (t.operation?.paths?.length) toParts.push(`路径: ${t.operation.paths.join(', ')}`)
            if (t.operation?.methods?.length) toParts.push(`方法: ${t.operation.methods.join(', ')}`)
          })
          const segs = [...fromParts, ...toParts]
          if (segs.length === 0) {
            return (
              <div key={idx} style={{ fontSize: 12, lineHeight: 1.8, color: '#8c8c8c' }}>
                无条件（匹配全部）
              </div>
            )
          }
          return (
            <div key={idx} style={{ fontSize: 12, lineHeight: 1.8 }}>
              {segs.map((s, i) => (
                <div key={i} style={{ marginBottom: i < segs.length - 1 ? 2 : 0 }}>{s}</div>
              ))}
            </div>
          )
        })}
      </div>
    )
  }

  const columns = [
    { title: '命名空间', dataIndex: 'namespace', key: 'namespace', width: 120 },
    { title: '名称', dataIndex: 'name', key: 'name', width: 160 },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 90,
      render: (v: string) => (
        <Tag color={v === 'ALLOW' ? 'green' : v === 'DENY' ? 'red' : 'default'}>{v || '-'}</Tag>
      ),
    },
    {
      title: '目标工作负载',
      dataIndex: 'workloadRef',
      key: 'workloadRef',
      width: 120,
      render: (v: string, r: AuthorizationPolicyItem) =>
        v || (r.selector && Object.keys(r.selector).length > 0 ? JSON.stringify(r.selector) : '-'),
    },
    {
      title: '规则详情',
      key: 'rulesDetail',
      render: (_: unknown, r: AuthorizationPolicyItem) => renderRuleDetail(r),
    },
    { title: '规则数', dataIndex: 'rulesCount', key: 'rulesCount', width: 80 },
  ]

  return (
    <Card
      title="授权策略列表"
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          刷新
        </Button>
      }
    >
      <Alert
        type="info"
        showIcon
        message="认证策略支持说明"
        description="Kmesh 当前支持 Istio AuthorizationPolicy（授权策略），可基于 IP、端口、命名空间等 L4 层条件控制访问。PeerAuthentication（mTLS 对等认证）与 RequestAuthentication（JWT 请求认证）计划在后续版本中支持。"
        style={{ marginBottom: 16 }}
      />
      <Input
        placeholder="按命名空间筛选（空=全部）"
        value={nsFilter}
        onChange={(e) => setNsFilter(e.target.value)}
        style={{ width: 220, marginBottom: 16 }}
      />
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
                    width: 90,
                    render: (_: unknown, r: AuthorizationPolicyItem) => (
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
