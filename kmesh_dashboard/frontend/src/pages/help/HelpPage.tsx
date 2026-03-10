import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Card, Menu, Spin, Alert } from 'antd'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { getDocsList, getDocContent } from '@/api/docs'

/** 与顶部导航顺序一致（从左到右）：集群节点、服务拓扑、Waypoint、熔断、认证策略、限流、指标 */
const DOC_ORDER = ['cluster', 'topology', 'waypoint', 'circuitbreaker', 'authorization', 'ratelimit', 'metrics'] as const

const DOC_LABELS: Record<string, string> = {
  cluster: '集群节点',
  topology: '服务拓扑',
  waypoint: 'Waypoint',
  circuitbreaker: '熔断',
  authorization: '认证策略',
  ratelimit: '限流',
  metrics: '指标',
}

function sortDocsByNavOrder(docs: string[]): string[] {
  const orderMap = new Map(DOC_ORDER.map((name, i) => [name, i]))
  return [...docs].sort((a, b) => {
    const ia = orderMap.get(a) ?? 999
    const ib = orderMap.get(b) ?? 999
    return ia - ib
  })
}

function docLabel(name: string): string {
  return DOC_LABELS[name] ?? name
}

export default function HelpPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const docName = searchParams.get('doc') || ''
  const [docList, setDocList] = useState<string[]>([])
  const [content, setContent] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getDocsList()
      .then((r) => {
        const sorted = sortDocsByNavOrder(r.docs || [])
        setDocList(sorted)
        const first = sorted[0]
        if (!docName && first) {
          setSearchParams({ doc: first }, { replace: true })
        }
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : '加载文档列表失败')
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!docName || !docList.includes(docName)) {
      if (docList.length > 0 && !docList.includes(docName)) {
        setContent('')
      }
      return
    }
    setLoading(true)
    setError(null)
    getDocContent(docName)
      .then(setContent)
      .catch((e) => {
        setError(e instanceof Error ? e.message : '加载文档失败')
        setContent('')
      })
      .finally(() => setLoading(false))
  }, [docName, docList])

  const onSelect = (key: string) => {
    setSearchParams({ doc: key })
  }

  if (loading && docList.length === 0) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}>
        <Spin size="large" />
      </div>
    )
  }

  if (error && docList.length === 0) {
    return (
      <Alert
        type="warning"
        message="文档不可用"
        description={error}
        showIcon
        style={{ marginBottom: 16 }}
      />
    )
  }

  return (
    <div style={{ display: 'flex', gap: 24, minHeight: 400 }}>
      <Card title="文档目录" style={{ width: 220, flexShrink: 0 }}>
        <Menu
          mode="inline"
          selectedKeys={[docName]}
          items={docList.map((name) => ({
            key: name,
            label: docLabel(name),
            onClick: () => onSelect(name),
          }))}
          style={{ border: 'none' }}
        />
      </Card>
      <Card
        title={docName ? docLabel(docName) : '选择文档'}
        style={{ flex: 1, minWidth: 0 }}
        loading={loading && !!docName}
      >
        {error && (
          <Alert type="error" message={error} style={{ marginBottom: 16 }} />
        )}
        {content ? (
          <div
            className="markdown-body"
            style={{
              lineHeight: 1.6,
              fontSize: 14,
            }}
          >
            <style>{`
              .markdown-body h1 { font-size: 1.5em; margin: 1em 0 0.5em; }
              .markdown-body h2 { font-size: 1.25em; margin: 1em 0 0.5em; }
              .markdown-body h3 { font-size: 1.1em; margin: 0.8em 0 0.4em; }
              .markdown-body p { margin: 0.5em 0; }
              .markdown-body ul, .markdown-body ol { margin: 0.5em 0; padding-left: 1.5em; }
              .markdown-body code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
              .markdown-body pre { background: #f5f5f5; padding: 12px; border-radius: 4px; overflow-x: auto; }
              .markdown-body pre code { background: none; padding: 0; }
            `}</style>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
          </div>
        ) : !docName ? (
          <div style={{ color: '#888' }}>请在左侧选择一篇文档</div>
        ) : null}
      </Card>
    </div>
  )
}
