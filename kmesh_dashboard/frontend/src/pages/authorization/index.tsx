import { useEffect, useState } from 'react'
import { Tabs, Space, Select } from 'antd'
import { getNamespaceList } from '@/api/cluster'
import AuthorizationListPage from './AuthorizationListPage'
import AuthorizationFormPage from './AuthorizationFormPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function AuthorizationPage() {
  const [namespaceOptions, setNamespaceOptions] = useState<string[]>([])
  const [selectedNamespace, setSelectedNamespace] = useState('default')

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
      <span>当前命名空间：</span>
      <Select
        value={selectedNamespace}
        onChange={setSelectedNamespace}
        options={namespaceOptions.map((ns) => ({ value: ns, label: ns }))}
        style={{ width: 160 }}
        placeholder="选择命名空间"
      />
    </Space>
  )

  const items = [
    { key: 'list', label: '策略列表', children: <AuthorizationListPage selectedNamespace={selectedNamespace} /> },
    {
      key: 'form',
      label: '配置授权策略',
      children: <AuthorizationFormPage selectedNamespace={selectedNamespace} namespaceOptions={namespaceOptions} />,
    },
    {
      key: 'yaml',
      label: '自定义 YAML',
      children: (
        <YamlApplyCard
          module="authorization"
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
