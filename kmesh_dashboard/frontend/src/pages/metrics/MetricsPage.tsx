import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card, Button, Alert, Space, Input, InputNumber, Statistic, Row, Col, Table, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { getMetricsDatasource, getMetricsOverview, getAccesslog, getKmeshPods } from '@/api/metrics'
import type { AccesslogEntry } from '@/types/metrics'

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB'
  if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB'
  return String(Math.round(bytes))
}

export default function MetricsPage() {
  const { t } = useTranslation()
  const [datasourceOk, setDatasourceOk] = useState(false)
  const [data, setData] = useState<{
    workloadConnOpened: number
    workloadConnClosed: number
    workloadRecvBytes: number
    workloadSentBytes: number
    workloadConnFailed: number
    serviceConnOpened: number
    serviceConnClosed: number
    serviceRecvBytes: number
    serviceSentBytes: number
    serviceConnFailed: number
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [namespace, setNamespace] = useState('')
  const [accesslogEntries, setAccesslogEntries] = useState<AccesslogEntry[]>([])
  const [accesslogMessage, setAccesslogMessage] = useState<string>('')
  const [accesslogPodsQueried, setAccesslogPodsQueried] = useState<string[]>([])
  const [accesslogLoading, setAccesslogLoading] = useState(false)
  const [accesslogPod, setAccesslogPod] = useState<string>('')
  const [accesslogTail, setAccesslogTail] = useState(200)
  const [kmeshPods, setKmeshPods] = useState<{ name: string; node: string; status: string }[]>([])
  const [kmeshPodsMsg, setKmeshPodsMsg] = useState('')

  const fetchDatasource = async () => {
    try {
      const res = await getMetricsDatasource()
      setDatasourceOk(res.available)
    } catch {
      setDatasourceOk(false)
    }
  }

  const fetchOverview = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getMetricsOverview({ namespace: namespace || undefined })
      if (!res.available) {
        setData(null)
        setError(res.message || t('metrics.prometheusUnavailable'))
      } else {
        setData({
          workloadConnOpened: res.workloadConnOpened ?? 0,
          workloadConnClosed: res.workloadConnClosed ?? 0,
          workloadRecvBytes: res.workloadRecvBytes ?? 0,
          workloadSentBytes: res.workloadSentBytes ?? 0,
          workloadConnFailed: res.workloadConnFailed ?? 0,
          serviceConnOpened: res.serviceConnOpened ?? 0,
          serviceConnClosed: res.serviceConnClosed ?? 0,
          serviceRecvBytes: res.serviceRecvBytes ?? 0,
          serviceSentBytes: res.serviceSentBytes ?? 0,
          serviceConnFailed: res.serviceConnFailed ?? 0,
        })
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : t('metrics.fetchFailed'))
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  const fetchKmeshPods = async () => {
    try {
      const res = await getKmeshPods()
      setKmeshPods(res.pods ?? [])
      setKmeshPodsMsg(res.message ?? '')
    } catch (e) {
      setKmeshPods([])
      setKmeshPodsMsg(e instanceof Error ? e.message : t('metrics.requestFailed'))
    }
  }

  const fetchAccesslog = async () => {
    setAccesslogLoading(true)
    setAccesslogMessage('')
    try {
      const res = await getAccesslog({
        pod: accesslogPod || undefined,
        tail: accesslogTail,
      })
      setAccesslogEntries(res.entries ?? [])
      setAccesslogPodsQueried(res.podsQueried ?? [])
      setAccesslogMessage(res.message ?? '')
    } catch (e) {
      setAccesslogEntries([])
      setAccesslogPodsQueried([])
      setAccesslogMessage(e instanceof Error ? e.message : t('metrics.requestFailed'))
    } finally {
      setAccesslogLoading(false)
    }
  }

  useEffect(() => {
    fetchDatasource()
  }, [])

  useEffect(() => {
    if (datasourceOk) fetchOverview()
    else setLoading(false)
  }, [datasourceOk, namespace])

  return (
    <div>
      <Card
        title={t('metrics.pageTitle')}
        extra={
          <Space>
            <Input
              placeholder={t('metrics.namespacePlaceholder')}
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              style={{ width: 180 }}
            />
            <Button type="primary" icon={<ReloadOutlined />} onClick={fetchOverview} loading={loading}>
              {t('common.refresh')}
            </Button>
          </Space>
        }
      >
        {!datasourceOk && (
          <Alert
            type="warning"
            message={t('metrics.noPrometheus')}
            description={t('metrics.noPrometheusDesc')}
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        {error && (
          <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
        )}
        {data && (
          <>
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>{t('metrics.workloadMetrics')}</div>
              <Row gutter={[16, 16]}>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connOpened')} value={data.workloadConnOpened} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connClosed')} value={data.workloadConnClosed} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.recvBytes')} value={formatBytes(data.workloadRecvBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.sentBytes')} value={formatBytes(data.workloadSentBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connFailed')} value={data.workloadConnFailed} />
                  </Card>
                </Col>
              </Row>
            </div>
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>{t('metrics.serviceMetrics')}</div>
              <Row gutter={[16, 16]}>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connOpened')} value={data.serviceConnOpened} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connClosed')} value={data.serviceConnClosed} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.recvBytes')} value={formatBytes(data.serviceRecvBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.sentBytes')} value={formatBytes(data.serviceSentBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title={t('metrics.connFailed')} value={data.serviceConnFailed} />
                  </Card>
                </Col>
              </Row>
            </div>
          </>
        )}
        <div style={{ marginTop: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>
            {t('metrics.accesslog')}
          </div>
          <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
            {t('metrics.accesslogTip')}
          </Typography.Text>
          <Space wrap style={{ marginBottom: 12 }}>
            <Button size="small" onClick={fetchKmeshPods}>
              {t('metrics.checkKmeshPods')}
            </Button>
            {kmeshPods.length > 0 && (
              <Typography.Text type="secondary">
                {t('metrics.foundPods', { count: kmeshPods.length, names: kmeshPods.map((p) => p.name).join(', ') })}
              </Typography.Text>
            )}
            {kmeshPodsMsg && kmeshPods.length === 0 && (
              <Typography.Text type="danger">{kmeshPodsMsg}</Typography.Text>
            )}
          </Space>
          {(accesslogMessage || (accesslogEntries.length === 0 && accesslogPodsQueried.length > 0)) && (
            <Alert
              type="info"
              message={accesslogPodsQueried.length > 0 ? t('metrics.queriedPods', { count: accesslogPodsQueried.length, names: accesslogPodsQueried.join(', ') }) : undefined}
              description={accesslogMessage}
              showIcon
              style={{ marginBottom: 12 }}
            />
          )}
          <Space wrap style={{ marginBottom: 16 }}>
            <Input
              placeholder={t('metrics.podPlaceholder')}
              value={accesslogPod}
              onChange={(e) => setAccesslogPod(e.target.value)}
              style={{ width: 180 }}
            />
            <InputNumber
              min={1}
              max={2000}
              value={accesslogTail}
              onChange={(v) => setAccesslogTail(v ?? 200)}
              placeholder={t('metrics.tailLines')}
              style={{ width: 100 }}
            />
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchAccesslog}
              loading={accesslogLoading}
            >
              {t('metrics.queryAccesslog')}
            </Button>
          </Space>
          <Table<AccesslogEntry>
            size="small"
            dataSource={accesslogEntries}
            rowKey={(_, i) => String(i)}
            columns={[
              { title: 'Pod', dataIndex: 'pod', width: 140, ellipsis: true },
              { title: 'Node', dataIndex: 'node', width: 120, ellipsis: true },
              {
                title: 'Content',
                dataIndex: 'content',
                render: (content: string) => (
                  <Typography.Text code copyable style={{ fontSize: 12 }}>
                    {content}
                  </Typography.Text>
                ),
              },
            ]}
            pagination={{ pageSize: 20, showSizeChanger: true }}
          />
        </div>
      </Card>
    </div>
  )
}
