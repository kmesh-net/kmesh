import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Modal, Tabs, Descriptions, Table, Tag, Spin, Alert, Empty, Collapse, Tooltip } from 'antd'
import { getPodDetail, getPodLogs, type PodDetailResponse, type PodLogsResponse } from '@/api/pod'

interface PodDetailModalProps {
  open: boolean
  namespace: string
  name: string
  onClose: () => void
  /** 指定日志容器名，如 Waypoint Pod 的 istio-proxy；不传则使用 Pod 第一个容器 */
  defaultLogContainer?: string
}

function FullTextCell({ text }: { text: string }) {
  if (!text) return <span style={{ color: '#999' }}>-</span>
  const truncated = text.length > 80 ? text.slice(0, 80) + '...' : text
  return (
    <Tooltip title={text} overlayInnerStyle={{ maxWidth: 500, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
      <span style={{ cursor: text.length > 80 ? 'help' : 'default', wordBreak: 'break-word' }}>{truncated}</span>
    </Tooltip>
  )
}

export default function PodDetailModal({ open, namespace, name, onClose, defaultLogContainer }: PodDetailModalProps) {
  const { t } = useTranslation()
  const [detail, setDetail] = useState<PodDetailResponse | null>(null)
  const [logs, setLogs] = useState<PodLogsResponse | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [loadingLogs, setLoadingLogs] = useState(false)
  const [activeTab, setActiveTab] = useState('detail')

  useEffect(() => {
    if (!open || !namespace || !name) return
    setDetail(null)
    setLogs(null)
    setActiveTab('detail')

    setLoadingDetail(true)
    getPodDetail(namespace, name)
      .then(setDetail)
      .catch(() => setDetail({ namespace, name, phase: '', error: t('pod.fetchDetailFailed') }))
      .finally(() => setLoadingDetail(false))
  }, [open, namespace, name])

  useEffect(() => {
    if (!open || !namespace || !name || activeTab !== 'logs') return
    setLoadingLogs(true)
    const container = defaultLogContainer ?? (detail?.containers?.[0]?.name)
    getPodLogs(namespace, name, { tail: 500, ...(container ? { container } : {}) })
      .then(setLogs)
      .catch(() => setLogs({ namespace, name, lines: [], error: t('pod.fetchLogsFailed') }))
      .finally(() => setLoadingLogs(false))
  }, [open, namespace, name, activeTab, defaultLogContainer, detail?.containers])

  const phaseColor: Record<string, string> = {
    Running: 'success',
    Pending: 'warning',
    Failed: 'error',
    Succeeded: 'success',
    Unknown: 'default',
  }

  const collapseItems = []
  if (detail && !detail.error) {
    collapseItems.push(
      {
        key: 'basic',
        label: t('pod.basicInfo'),
        children: (
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="Phase">
              <Tag color={phaseColor[detail.phase] ?? 'default'}>{detail.phase}</Tag>
            </Descriptions.Item>
            {detail.reason && <Descriptions.Item label="Reason">{detail.reason}</Descriptions.Item>}
            {detail.message && (
              <Descriptions.Item label="Message">
                <FullTextCell text={detail.message} />
              </Descriptions.Item>
            )}
            {detail.node && <Descriptions.Item label="Node">{detail.node}</Descriptions.Item>}
            {detail.podIP && <Descriptions.Item label="Pod IP">{detail.podIP}</Descriptions.Item>}
            {detail.startTime && <Descriptions.Item label="Start Time">{detail.startTime}</Descriptions.Item>}
          </Descriptions>
        ),
      },
      ...(detail.labels && Object.keys(detail.labels).length > 0
        ? [
            {
              key: 'labels',
              label: `Labels (${Object.keys(detail.labels).length})`,
              children: (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(detail.labels).map(([k, v]) => (
                    <Tag key={k}>{k}={v}</Tag>
                  ))}
                </div>
              ),
            },
          ]
        : []),
      ...(detail.annotations && Object.keys(detail.annotations).length > 0
        ? [
            {
              key: 'annotations',
              label: `Annotations (${Object.keys(detail.annotations).length})`,
              children: (
                <Descriptions column={1} size="small" bordered>
                  {Object.entries(detail.annotations).map(([k, v]) => (
                    <Descriptions.Item key={k} label={k}>
                      <FullTextCell text={v} />
                    </Descriptions.Item>
                  ))}
                </Descriptions>
              ),
            },
          ]
        : []),
      ...(detail.containers && detail.containers.length > 0
        ? [
            {
              key: 'containers',
              label: `${t('pod.containerStatus')} (${detail.containers.length})`,
              children: (
                <Table
                  size="small"
                  dataSource={detail.containers}
                  columns={[
                    { title: t('pod.container'), dataIndex: 'name', key: 'name', width: 120 },
                    { title: 'Image', dataIndex: 'image', key: 'image', ellipsis: true, render: (v: string) => <FullTextCell text={v || ''} /> },
                    {
                      title: t('pod.state'),
                      dataIndex: 'state',
                      key: 'state',
                      width: 90,
                      render: (s: string) => (
                        <Tag color={s === 'Running' ? 'success' : s === 'Waiting' ? 'warning' : 'default'}>{s}</Tag>
                      ),
                    },
                    { title: 'Ready', dataIndex: 'ready', key: 'ready', width: 60, render: (v: boolean) => (v ? t('common.yes') : t('common.no')) },
                    { title: t('pod.restartCount'), dataIndex: 'restartCount', key: 'restartCount', width: 60 },
                    { title: 'Reason', dataIndex: 'reason', key: 'reason', render: (v: string) => <FullTextCell text={v || ''} /> },
                    { title: 'Message', dataIndex: 'message', key: 'message', render: (v: string) => <FullTextCell text={v || ''} /> },
                    { title: 'Last State', dataIndex: 'lastState', key: 'lastState', render: (v: string) => <FullTextCell text={v || ''} /> },
                    { title: 'Started', dataIndex: 'startedAt', key: 'startedAt', width: 160 },
                    { title: 'Finished', dataIndex: 'finishedAt', key: 'finishedAt', width: 160 },
                  ]}
                  pagination={false}
                />
              ),
            },
          ]
        : []),
      ...(detail.conditions && detail.conditions.length > 0
        ? [
            {
              key: 'conditions',
              label: `Conditions (${detail.conditions.length})`,
              children: (
                <Table
                  size="small"
                  dataSource={detail.conditions}
                  columns={[
                    { title: 'Type', dataIndex: 'type', key: 'type', width: 140 },
                    {
                      title: 'Status',
                      dataIndex: 'status',
                      key: 'status',
                      width: 80,
                      render: (s: string) => (
                        <Tag color={s === 'True' ? 'success' : 'warning'}>{s}</Tag>
                      ),
                    },
                    { title: 'Reason', dataIndex: 'reason', key: 'reason', render: (v: string) => <FullTextCell text={v || ''} /> },
                    { title: 'Message', dataIndex: 'message', key: 'message', render: (v: string) => <FullTextCell text={v || ''} /> },
                    { title: 'Last Transition', dataIndex: 'lastTransitionTime', key: 'lastTransitionTime', width: 160 },
                  ]}
                  pagination={false}
                />
              ),
            },
          ]
        : []),
      ...(detail.events && detail.events.length > 0
        ? [
            {
              key: 'events',
              label: `Events (${detail.events.length})`,
              children: (
                <Table
                  size="small"
                  dataSource={detail.events}
                  scroll={{ x: 900 }}
                  columns={[
                    { title: 'First Seen', dataIndex: 'firstSeen', key: 'firstSeen', width: 160 },
                    { title: 'Last Seen', dataIndex: 'lastSeen', key: 'lastSeen', width: 160 },
                    {
                      title: 'Type',
                      dataIndex: 'type',
                      key: 'type',
                      width: 80,
                      render: (t: string) => (
                        <Tag color={t === 'Warning' ? 'warning' : 'default'}>{t}</Tag>
                      ),
                    },
                    { title: 'Reason', dataIndex: 'reason', key: 'reason', width: 140 },
                    { title: 'Source', dataIndex: 'source', key: 'source', width: 120, ellipsis: true },
                    { title: 'Count', dataIndex: 'count', key: 'count', width: 70 },
                    {
                      title: 'Message',
                      dataIndex: 'message',
                      key: 'message',
                      width: 280,
                      render: (v: string) => <FullTextCell text={v || ''} />,
                    },
                  ]}
                  pagination={false}
                />
              ),
            },
          ]
        : []),
    )
  }

  return (
    <Modal
      title={`Pod: ${namespace}/${name}`}
      open={open}
      onCancel={onClose}
      footer={null}
      width={960}
      destroyOnClose
      styles={{ body: { maxHeight: '70vh', overflow: 'auto' } }}
    >
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'detail',
            label: t('pod.detail'),
            children: (
              <Spin spinning={loadingDetail}>
                {detail?.error ? (
                  <Alert type="error" message={detail.error} />
                ) : detail ? (
                  <div>
                    {collapseItems.length > 0 ? (
                      <Collapse items={collapseItems} defaultActiveKey={['basic', 'containers', 'events']} />
                    ) : (
                      <Empty description={t('pod.noDetail')} />
                    )}
                    {detail.events?.length === 0 && !detail.error && (
                      <div style={{ color: '#999', marginTop: 16 }}>{t('pod.noEvents')}</div>
                    )}
                  </div>
                ) : (
                  <Empty description={t('common.loading')} />
                )}
              </Spin>
            ),
          },
          {
            key: 'logs',
            label: t('pod.logs'),
            children: (
              <Spin spinning={loadingLogs}>
                {logs?.error ? (
                  <Alert type="error" message={logs.error} />
                ) : logs ? (
                  <pre
                    style={{
                      maxHeight: 500,
                      overflow: 'auto',
                      background: '#1e1e1e',
                      color: '#d4d4d4',
                      padding: 12,
                      borderRadius: 6,
                      fontSize: 12,
                      margin: 0,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {logs.lines.length > 0 ? logs.lines.join('\n') : t('pod.noLogs')}
                  </pre>
                ) : (
                  <Empty description={t('pod.switchToLogs')} />
                )}
              </Spin>
            ),
          },
        ]}
      />
    </Modal>
  )
}
