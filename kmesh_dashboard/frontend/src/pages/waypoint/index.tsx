import { useEffect, useState } from 'react'
import { Tabs, Space, Select, Checkbox } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import { getNamespaceList } from '@/api/cluster'
import WaypointListPage from './WaypointListPage'
import WaypointApplyPage from './WaypointApplyPage'
import YamlApplyCard from '@/components/customYaml/YamlApplyCard'

export default function WaypointPage() {
  const { can } = useAuth()
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

  // 当命名空间列表加载后，若当前选择不在列表中则切换到第一项
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
      label: '列表与状态',
      children: (
        <WaypointListPage
          selectedNamespace={selectedNamespace}
          allNamespaces={allNamespaces}
        />
      ),
    },
    ...(can('waypoint', 'write')
      ? [
          {
            key: 'apply',
            label: '安装 Waypoint',
            children: (
              <WaypointApplyPage
                selectedNamespace={selectedNamespace}
                namespaceOptions={namespaceOptions}
              />
            ),
          },
        ]
      : []),
    ...(can('custom', 'write')
      ? [
          {
            key: 'yaml',
            label: '自定义 YAML',
            children: (
              <YamlApplyCard
                module="waypoint"
                namespace={selectedNamespace}
                onSuccess={() => {}}
              />
            ),
          },
        ]
      : []),
  ]
  return (
    <>
      {header}
      <Tabs items={items} />
    </>
  )
}
