import { useState, useEffect } from 'react'
import { Card, Button, Alert, Space, message } from 'antd'
import { ThunderboltOutlined, CheckOutlined, FileTextOutlined } from '@ant-design/icons'
import Editor from '@monaco-editor/react'
import { useTranslation } from 'react-i18next'
import {
  getCustomYamlTemplate,
  validateCustomYaml,
  applyCustomYaml,
  type CustomYamlModule,
} from '@/api/customYaml'

const MODULE_KEYS: Record<CustomYamlModule, string> = {
  circuitbreaker: 'yamlApply.circuitbreaker',
  ratelimit: 'yamlApply.ratelimit',
  authorization: 'yamlApply.authorization',
  waypoint: 'yamlApply.waypoint',
}

interface YamlApplyCardProps {
  module: CustomYamlModule
  namespace: string
  onSuccess?: () => void
}

export default function YamlApplyCard({ module, namespace, onSuccess }: YamlApplyCardProps) {
  const { t } = useTranslation()
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
      .catch(() => message.error(t('yamlApply.loadTemplateFailed')))
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
      .catch(() => setValidateResult({ valid: false, error: t('yamlApply.validateFailed') }))
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
          setApplySuccess(res.message || t('yamlApply.applySuccess'))
          onSuccess?.()
        }
      })
      .catch((e) => setApplyError(e instanceof Error ? e.message : t('yamlApply.applyFailed')))
      .finally(() => setLoadingApply(false))
  }

  return (
    <Card
      title={
        <Space>
          <FileTextOutlined />
          <span>{t('yamlApply.title')}</span>
          <span style={{ color: '#999', fontWeight: 400, fontSize: 13 }}>
            — {t(MODULE_KEYS[module])}
          </span>
        </Space>
      }
      extra={
        <Button size="small" onClick={loadTemplate} loading={loadingTemplate}>
          {t('yamlApply.loadTemplate')}
        </Button>
      }
    >
      <p style={{ color: '#666', marginBottom: 12, fontSize: 13 }}>
        {t('yamlApply.desc')}
      </p>
      {validateResult && (
        <Alert
          type={validateResult.valid ? 'success' : 'error'}
          message={validateResult.valid ? t('yamlApply.validateSuccess') : validateResult.error}
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
          loading={t('yamlApply.editorLoading')}
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
          {t('yamlApply.validate')}
        </Button>
        <Button
          type="primary"
          icon={<ThunderboltOutlined />}
          onClick={handleApply}
          loading={loadingApply}
        >
          {t('yamlApply.applyToCluster')}
        </Button>
      </Space>
    </Card>
  )
}
