import { useState, useEffect } from 'react'
import { Card, Button, Alert, Space, message } from 'antd'
import { ThunderboltOutlined, CheckOutlined, FileTextOutlined } from '@ant-design/icons'
import Editor from '@monaco-editor/react'
import {
  getCustomYamlTemplate,
  validateCustomYaml,
  applyCustomYaml,
  type CustomYamlModule,
} from '@/api/customYaml'

const MODULE_LABELS: Record<CustomYamlModule, string> = {
  circuitbreaker: '熔断 (DestinationRule)',
  ratelimit: '限流 (EnvoyFilter)',
  authorization: '认证策略 (AuthorizationPolicy)',
  waypoint: 'Waypoint (Gateway)',
}

interface YamlApplyCardProps {
  module: CustomYamlModule
  namespace: string
  onSuccess?: () => void
}

export default function YamlApplyCard({ module, namespace, onSuccess }: YamlApplyCardProps) {
  const [yaml, setYaml] = useState('')
  const [loadingTemplate, setLoadingTemplate] = useState(false)
  const [loadingValidate, setLoadingValidate] = useState(false)
  const [loadingApply, setLoadingApply] = useState(false)
  const [validateResult, setValidateResult] = useState<{ valid: boolean; error?: string } | null>(null)
  const [applyError, setApplyError] = useState<string | null>(null)
  const [applySuccess, setApplySuccess] = useState<string | null>(null)

  const loadTemplate = () => {
    setLoadingTemplate(true)
    setValidateResult(null)
    setApplyError(null)
    setApplySuccess(null)
    getCustomYamlTemplate(module)
      .then((res) => setYaml(res.yaml))
      .catch(() => message.error('加载模板失败'))
      .finally(() => setLoadingTemplate(false))
  }

  useEffect(() => {
    loadTemplate()
  }, [module])

  const handleValidate = () => {
    setLoadingValidate(true)
    setValidateResult(null)
    validateCustomYaml(module, yaml)
      .then((res) => setValidateResult({ valid: res.valid, error: res.error }))
      .catch(() => setValidateResult({ valid: false, error: '校验请求失败' }))
      .finally(() => setLoadingValidate(false))
  }

  const handleApply = () => {
    setLoadingApply(true)
    setApplyError(null)
    setApplySuccess(null)
    applyCustomYaml(module, namespace || 'default', yaml)
      .then((res) => {
        if (res.error) {
          setApplyError(res.error)
        } else {
          setApplySuccess(res.message || '已成功应用到集群')
          onSuccess?.()
        }
      })
      .catch((e) => setApplyError(e instanceof Error ? e.message : '应用失败'))
      .finally(() => setLoadingApply(false))
  }

  return (
    <Card
      title={
        <Space>
          <FileTextOutlined />
          <span>自定义 YAML 一键应用</span>
          <span style={{ color: '#999', fontWeight: 400, fontSize: 13 }}>
            — {MODULE_LABELS[module]}
          </span>
        </Space>
      }
      extra={
        <Button size="small" onClick={loadTemplate} loading={loadingTemplate}>
          加载默认模板
        </Button>
      }
    >
      <p style={{ color: '#666', marginBottom: 12, fontSize: 13 }}>
        编辑下方 YAML，支持 Dashboard 未提供的额外字段。应用前会校验格式。
      </p>
      {validateResult && (
        <Alert
          type={validateResult.valid ? 'success' : 'error'}
          message={validateResult.valid ? '格式校验通过' : validateResult.error}
          showIcon
          style={{ marginBottom: 12 }}
        />
      )}
      {applyError && <Alert type="error" message={applyError} showIcon style={{ marginBottom: 12 }} />}
      {applySuccess && (
        <Alert type="success" message={applySuccess} showIcon style={{ marginBottom: 12 }} />
      )}
      <div style={{ border: '1px solid #d9d9d9', borderRadius: 6, overflow: 'hidden', marginBottom: 12 }}>
        <Editor
          height={420}
          language="yaml"
          value={yaml}
          loading="编辑器加载中..."
          onChange={(value) => {
            setYaml(value ?? '')
            setValidateResult(null)
            setApplyError(null)
            setApplySuccess(null)
          }}
          theme="light"
          options={{
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbers: 'on',
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            folding: true,
            tabSize: 2,
            padding: { top: 12 },
          }}
        />
      </div>
      <Space>
        <Button
          icon={<CheckOutlined />}
          onClick={handleValidate}
          loading={loadingValidate}
        >
          校验格式
        </Button>
        <Button
          type="primary"
          icon={<ThunderboltOutlined />}
          onClick={handleApply}
          loading={loadingApply}
        >
          应用到集群
        </Button>
      </Space>
    </Card>
  )
}
