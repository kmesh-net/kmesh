import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Table, Button, Spin, Alert, Tag } from 'antd'
import { ReloadOutlined, DeleteOutlined } from '@ant-design/icons'
import { getAuthorizationList, deleteAuthorizationPolicy } from '@/api/authorization'
import type { AuthorizationPolicyItem } from '@/types/authorization'

interface AuthorizationListPageProps {
  selectedNamespace: string
}

export default function AuthorizationListPage({ selectedNamespace }: AuthorizationListPageProps) {
  const { t } = useTranslation()
  const [list, setList] = useState<AuthorizationPolicyItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchList = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getAuthorizationList(selectedNamespace || undefined)
      setList(res.items)
    } catch (e) {
      setError(e instanceof Error ? e.message : t('authorization.fetchFailed'))
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
      setError(e instanceof Error ? e.message : t('authorization.deleteFailed'))
    } finally {
      setDeleting(null)
    }
  }

  useEffect(() => {
    fetchList()
  }, [selectedNamespace])

  const renderRuleDetail = (item: AuthorizationPolicyItem) => {
    if (!item.rules || item.rules.length === 0) return '-'
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 360 }}>
        {item.rules.map((rule, idx) => {
          const fromParts: string[] = []
          rule.from?.forEach((f) => {
            if (f.source?.ipBlocks?.length) fromParts.push(`${t('authorization.ruleLabelIp')}: ${f.source.ipBlocks.join(', ')}`)
            if (f.source?.namespaces?.length) fromParts.push(`${t('authorization.ruleLabelNs')}: ${f.source.namespaces.join(', ')}`)
            if (f.source?.principals?.length) fromParts.push(`${t('authorization.ruleLabelPrincipal')}: ${f.source.principals.join(', ')}`)
          })
          const toParts: string[] = []
          rule.to?.forEach((to) => {
            if (to.operation?.ports?.length) toParts.push(`${t('authorization.ruleLabelPorts')}: ${to.operation.ports.join(', ')}`)
            if (to.operation?.hosts?.length) toParts.push(`${t('authorization.ruleLabelHosts')}: ${to.operation.hosts.join(', ')}`)
            if (to.operation?.paths?.length) toParts.push(`${t('authorization.ruleLabelPaths')}: ${to.operation.paths.join(', ')}`)
            if (to.operation?.methods?.length) toParts.push(`${t('authorization.ruleLabelMethods')}: ${to.operation.methods.join(', ')}`)
          })
          const segs = [...fromParts, ...toParts]
          if (segs.length === 0) {
            return (
              <div key={idx} style={{ fontSize: 12, lineHeight: 1.8, color: '#8c8c8c' }}>
                {t('authorization.noRuleMatch')}
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
    { title: t('common.name'), dataIndex: 'name', key: 'name', width: 160 },
    {
      title: t('authorization.action'),
      dataIndex: 'action',
      key: 'action',
      width: 90,
      render: (v: string) => (
        <Tag color={v === 'ALLOW' ? 'green' : v === 'DENY' ? 'red' : 'default'}>{v || '-'}</Tag>
      ),
    },
    {
      title: t('authorization.targetWorkload'),
      dataIndex: 'workloadRef',
      key: 'workloadRef',
      width: 120,
      render: (v: string, r: AuthorizationPolicyItem) =>
        v || (r.selector && Object.keys(r.selector).length > 0 ? JSON.stringify(r.selector) : '-'),
    },
    {
      title: t('authorization.rulesDetail'),
      key: 'rulesDetail',
      render: (_: unknown, r: AuthorizationPolicyItem) => renderRuleDetail(r),
    },
    { title: t('authorization.rulesCount'), dataIndex: 'rulesCount', key: 'rulesCount', width: 80 },
  ]

  return (
    <Card
      title={t('authorization.listTitle')}
      extra={
        <Button type="primary" icon={<ReloadOutlined />} onClick={fetchList} loading={loading}>
          {t('common.refresh')}
        </Button>
      }
    >
      <Alert
        type="info"
        showIcon
        message={t('authorization.supportTipTitle')}
        description={t('authorization.supportTip')}
        style={{ marginBottom: 16 }}
      />
      {error && (
        <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
      )}
      <Spin spinning={loading}>
        <Table
          rowKey={(r) => `${r.namespace}/${r.name}`}
          columns={[
            ...columns,
            {
              title: t('common.operation'),
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
