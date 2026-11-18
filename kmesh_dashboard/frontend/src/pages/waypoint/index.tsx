import { useEffect, useState } from 'react'
import { Tabs, Space, Select, Checkbox } from 'antd'
import { useTranslation } from 'react-i18next'
import { getNamespaceList } from '@/api/cluster'
import WaypointListPage from './WaypointListPage'
import WaypointApplyPage from './WaypointApplyPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function WaypointPage() {
  const { t } = useTranslation()
  const [namespaceOptions, setNamespaceOptions] = useState<string[]>([])
  const [selectedNamespace, setSelectedNamespace] = useState('default')
  const [allNamespaces, setAllNamespaces] = useState(true)

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

  // After namespaces are loaded, fall back to the first one if current selection is missing.
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
      label: t('waypoint.listAndStatus'),
      children: (
        <WaypointListPage
          selectedNamespace={selectedNamespace}
          allNamespaces={allNamespaces}
        />
      ),
    },
    {
      key: 'apply',
      label: t('waypoint.install'),
      children: (
        <WaypointApplyPage
          selectedNamespace={selectedNamespace}
          namespaceOptions={namespaceOptions}
        />
      ),
    },
    {
      key: 'yaml',
      label: t('waypoint.customYaml'),
      children: (
        <YamlApplyCard
          module="waypoint"
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
