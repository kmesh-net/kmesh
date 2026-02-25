import { useEffect, useState } from 'react'
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
        setError(res.message || 'Prometheus 不可用')
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
      setError(e instanceof Error ? e.message : '获取指标失败')
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
      setKmeshPodsMsg(e instanceof Error ? e.message : '请求失败')
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
      setAccesslogMessage(e instanceof Error ? e.message : '请求失败')
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
        title="服务网格指标"
        extra={
          <Space>
            <Input
              placeholder="命名空间（空=全部）"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              style={{ width: 180 }}
            />
            <Button type="primary" icon={<ReloadOutlined />} onClick={fetchOverview} loading={loading}>
              刷新
            </Button>
          </Space>
        }
      >
        {!datasourceOk && (
          <Alert
            type="warning"
            message="未配置 Prometheus"
            description="请在后端设置环境变量 PROMETHEUS_URL 以拉取 Kmesh L4 指标（工作负载/服务累计值）。"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        {error && (
          <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
        )}
        {data && (
          <>
            {/* Kmesh L4 工作负载指标（累计值） */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>工作负载指标</div>
              <Row gutter={[16, 16]}>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接打开总数" value={data.workloadConnOpened} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接关闭总数" value={data.workloadConnClosed} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="接收字节总数" value={formatBytes(data.workloadRecvBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="发送字节总数" value={formatBytes(data.workloadSentBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接失败总数" value={data.workloadConnFailed} />
                  </Card>
                </Col>
              </Row>
            </div>
            {/* Kmesh L4 服务指标（累计值） */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>服务指标</div>
              <Row gutter={[16, 16]}>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接打开总数" value={data.serviceConnOpened} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接关闭总数" value={data.serviceConnClosed} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="接收字节总数" value={formatBytes(data.serviceRecvBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="发送字节总数" value={formatBytes(data.serviceSentBytes)} />
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={4}>
                  <Card size="small">
                    <Statistic title="连接失败总数" value={data.serviceConnFailed} />
                  </Card>
                </Col>
              </Row>
            </div>
          </>
        )}
        {/* Accesslog：从 kmesh pods 日志直连获取 */}
        <div style={{ marginTop: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, color: 'rgba(0,0,0,0.85)' }}>
            Accesslog
          </div>
          <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
            从 kmesh daemon pods 的容器日志中筛选 accesslog。需先执行 kmeshctl monitoring --all enable，再执行 kmeshctl monitoring --accesslog enable，并产生 TCP 流量。
          </Typography.Text>
          <Space wrap style={{ marginBottom: 12 }}>
            <Button size="small" onClick={fetchKmeshPods}>
              检查 kmesh pods
            </Button>
            {kmeshPods.length > 0 && (
              <Typography.Text type="secondary">
                发现 {kmeshPods.length} 个 pod：{kmeshPods.map((p) => p.name).join(', ')}
              </Typography.Text>
            )}
            {kmeshPodsMsg && kmeshPods.length === 0 && (
              <Typography.Text type="danger">{kmeshPodsMsg}</Typography.Text>
            )}
          </Space>
          {(accesslogMessage || (accesslogEntries.length === 0 && accesslogPodsQueried.length > 0)) && (
            <Alert
              type="info"
              message={accesslogPodsQueried.length > 0 ? `已查询 ${accesslogPodsQueried.length} 个 pod：${accesslogPodsQueried.join(', ')}` : undefined}
              description={accesslogMessage}
              showIcon
              style={{ marginBottom: 12 }}
            />
          )}
          <Space wrap style={{ marginBottom: 16 }}>
            <Input
              placeholder="Pod 名称（空=全部）"
              value={accesslogPod}
              onChange={(e) => setAccesslogPod(e.target.value)}
              style={{ width: 180 }}
            />
            <InputNumber
              min={1}
              max={2000}
              value={accesslogTail}
              onChange={(v) => setAccesslogTail(v ?? 200)}
              placeholder="最近行数"
              style={{ width: 100 }}
            />
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchAccesslog}
              loading={accesslogLoading}
            >
              查询 Accesslog
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
                render: (t: string) => (
                  <Typography.Text code copyable style={{ fontSize: 12 }}>
                    {t}
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
