import { useEffect, useState } from 'react'
import { Card, Select, Button, Alert, Space, Input } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { getMetricsDatasource, getMetricsOverview } from '@/api/metrics'
import type { MetricsPoint } from '@/types/metrics'

const TIME_RANGES = [
  { value: '5m', label: '最近 5 分钟', step: 15 },
  { value: '15m', label: '最近 15 分钟', step: 30 },
  { value: '1h', label: '最近 1 小时', step: 60 },
]

function lineOption(title: string, data: MetricsPoint[], unit = '', isPercent = false) {
  return {
    title: { text: title, left: 'center' },
    tooltip: {
      trigger: 'axis',
      valueFormatter: isPercent ? (v: number) => (Number(v) * 100).toFixed(2) + '%' : undefined,
    },
    grid: { left: 48, right: 24, top: 40, bottom: 32 },
    xAxis: {
      type: 'time',
      axisLabel: { formatter: (v: number) => new Date(v).toLocaleTimeString() },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: isPercent ? 1 : undefined,
      axisLabel: {
        formatter: isPercent ? (v: number) => (Number(v) * 100).toFixed(0) + '%' : unit ? `{value} ${unit}` : '{value}',
      },
    },
    series: [
      { name: title, type: 'line', smooth: true, data: data.map((p) => [p.time * 1000, isPercent ? p.value : p.value]) },
    ],
  }
}

export default function MetricsPage() {
  const [datasourceOk, setDatasourceOk] = useState(false)
  const [data, setData] = useState<{
    connOpenedRate: MetricsPoint[]
    connClosedRate: MetricsPoint[]
    bytesSentRate: MetricsPoint[]
    bytesRecvRate: MetricsPoint[]
    connFailedRate: MetricsPoint[]
    rps: MetricsPoint[]
    errorRate: MetricsPoint[]
    latencyP50: MetricsPoint[]
    latencyP95: MetricsPoint[]
    latencyP99: MetricsPoint[]
    message?: string
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState('15m')
  const [namespace, setNamespace] = useState('')

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
    const range = TIME_RANGES.find((r) => r.value === timeRange) ?? TIME_RANGES[1]
    const end = Math.floor(Date.now() / 1000)
    const start = timeRange === '5m' ? end - 5 * 60 : timeRange === '15m' ? end - 15 * 60 : end - 3600
    try {
      const res = await getMetricsOverview({
        namespace: namespace || undefined,
        start,
        end,
        step: range.step,
      })
      if (!res.available) {
        setData(null)
        setError(res.message || 'Prometheus 不可用')
      } else {
        setData({
          connOpenedRate: res.connOpenedRate ?? [],
          connClosedRate: res.connClosedRate ?? [],
          bytesSentRate: res.bytesSentRate ?? [],
          bytesRecvRate: res.bytesRecvRate ?? [],
          connFailedRate: res.connFailedRate ?? [],
          rps: res.rps ?? [],
          errorRate: res.errorRate ?? [],
          latencyP50: res.latencyP50 ?? [],
          latencyP95: res.latencyP95 ?? [],
          latencyP99: res.latencyP99 ?? [],
          message: res.message,
        })
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : '获取指标失败')
      setData(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDatasource()
  }, [])

  useEffect(() => {
    if (datasourceOk) fetchOverview()
    else setLoading(false)
  }, [datasourceOk, timeRange, namespace])

  return (
    <div>
      <Card
        title="服务网格指标"
        extra={
          <Space>
            <Select
              value={timeRange}
              onChange={setTimeRange}
              options={TIME_RANGES}
              style={{ width: 140 }}
            />
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
            description="请在后端设置环境变量 PROMETHEUS_URL 以拉取 Kmesh L4 与 Istio L7 指标（throughput / error rates / latency）。"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        {error && (
          <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />
        )}
        {data && (
          <>
            {/* Throughput 吞吐：RPS + L4 字节/连接 */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'rgba(0,0,0,0.85)' }}>Throughput / 吞吐</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                <Card size="small">
                  <ReactECharts option={lineOption('请求量 RPS (L7)', data.rps)} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('连接建立速率 (L4)', data.connOpenedRate, '/s')} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('发送字节率 (L4)', data.bytesSentRate, 'B/s')} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('接收字节率 (L4)', data.bytesRecvRate, 'B/s')} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('连接关闭速率 (L4)', data.connClosedRate, '/s')} style={{ height: 220 }} notMerge />
                </Card>
              </div>
            </div>
            {/* Error rates 错误率 */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'rgba(0,0,0,0.85)' }}>Error rates / 错误率</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
                <Card size="small">
                  <ReactECharts option={lineOption('5xx 错误率 (L7)', data.errorRate, '', true)} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('连接失败速率 (L4)', data.connFailedRate, '/s')} style={{ height: 220 }} notMerge />
                </Card>
              </div>
            </div>
            {/* Latency 延迟 */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: 'rgba(0,0,0,0.85)' }}>Latency / 延迟 (L7)</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                <Card size="small">
                  <ReactECharts option={lineOption('P50', data.latencyP50, 'ms')} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('P95', data.latencyP95, 'ms')} style={{ height: 220 }} notMerge />
                </Card>
                <Card size="small">
                  <ReactECharts option={lineOption('P99', data.latencyP99, 'ms')} style={{ height: 220 }} notMerge />
                </Card>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  )
}
