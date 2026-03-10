import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Tabs, Space, Select, Checkbox } from 'antd'
import { getNamespaceList } from '@/api/cluster'
import RateLimitListPage from './RateLimitListPage'
import RateLimitFormPage from './RateLimitFormPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function RateLimitPage() {
  const { t } = useTranslation()
  const [namespaceOptions, setNamespaceOptions] = useState<string[]>([])
  const [selectedNamespace, setSelectedNamespace] = useState('default')
  const [allNamespaces, setAllNamespaces] = useState(false)

  useEffect(() => {
    getNamespaceList()
      .then((res) => {
        const items = res.items || []
        setNamespaceOptions(items)
        if (items.length > 0 && !items.includes(selectedNamespace)) {
          setSelectedNamespace(items[0])
        }
      })
      .catch(() => setNamespaceOptions([]))
  }, [])

  useEffect(() => {
    if (namespaceOptions.length > 0 && !namespaceOptions.includes(selectedNamespace)) {
      setSelectedNamespace(namespaceOptions[0])
    }
  }, [namespaceOptions])

  const header = (
    <Space style={{ marginBottom: 16 }}>
      <Space>
        <span>{t('common.currentNamespace')}</span>
        <Select
          value={selectedNamespace}
          onChange={setSelectedNamespace}
          options={namespaceOptions.map((ns) => ({ value: ns, label: ns }))}
          style={{ width: 160 }}
          placeholder={t('common.selectNamespace')}
        />
      </Space>
      <Checkbox checked={allNamespaces} onChange={(e) => setAllNamespaces(e.target.checked)}>
        {t('waypoint.showAllNamespaces')}
      </Checkbox>
    </Space>
  )

  const items = [
    {
      key: 'list',
      label: t('ratelimit.policyList'),
      children: (
        <RateLimitListPage
          selectedNamespace={selectedNamespace}
          allNamespaces={allNamespaces}
        />
      ),
    },
    {
      key: 'form',
      label: t('ratelimit.config'),
      children: <RateLimitFormPage selectedNamespace={selectedNamespace} namespaceOptions={namespaceOptions} />,
    },
    {
      key: 'yaml',
      label: t('common.customYaml'),
      children: (
        <YamlApplyCard
          module="ratelimit"
          namespace={selectedNamespace}
          onSuccess={() => {}}
        />
      ),
    },
  ]
  return (
    <>
      {header}
      <Tabs items={items} />
    </>
  )
}
