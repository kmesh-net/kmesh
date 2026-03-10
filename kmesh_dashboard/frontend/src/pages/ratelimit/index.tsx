import { useEffect, useState } from 'react'
import { Tabs, Space, Select, Checkbox } from 'antd'
import { getNamespaceList } from '@/api/cluster'
import RateLimitListPage from './RateLimitListPage'
import RateLimitFormPage from './RateLimitFormPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function RateLimitPage() {
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
        <span>当前命名空间：</span>
        <Select
          value={selectedNamespace}
          onChange={setSelectedNamespace}
          options={namespaceOptions.map((ns) => ({ value: ns, label: ns }))}
          style={{ width: 160 }}
          placeholder="选择命名空间"
        />
      </Space>
      <Checkbox checked={allNamespaces} onChange={(e) => setAllNamespaces(e.target.checked)}>
        列表显示全部命名空间
      </Checkbox>
    </Space>
  )

  const items = [
    {
      key: 'list',
      label: '策略列表',
      children: (
        <RateLimitListPage
          selectedNamespace={selectedNamespace}
          allNamespaces={allNamespaces}
        />
      ),
    },
    {
      key: 'form',
      label: '配置限流',
      children: <RateLimitFormPage selectedNamespace={selectedNamespace} namespaceOptions={namespaceOptions} />,
    },
    {
      key: 'yaml',
      label: '自定义 YAML',
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
