import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Tabs, Space, Select, Checkbox } from 'antd'
import { getNamespaceList } from '@/api/cluster'
import CircuitBreakerListPage from './CircuitBreakerListPage'
import CircuitBreakerFormPage from './CircuitBreakerFormPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function CircuitBreakerPage() {
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
      label: t('circuitbreaker.policyList'),
      children: (
        <CircuitBreakerListPage
          selectedNamespace={selectedNamespace}
          allNamespaces={allNamespaces}
        />
      ),
    },
    {
      key: 'form',
      label: t('circuitbreaker.config'),
      children: <CircuitBreakerFormPage selectedNamespace={selectedNamespace} namespaceOptions={namespaceOptions} />,
    },
    {
      key: 'yaml',
      label: t('common.customYaml'),
      children: (
        <YamlApplyCard
          module="circuitbreaker"
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
