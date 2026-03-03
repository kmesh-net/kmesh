import { useEffect, useState } from 'react'
import { Tabs, Space, Select } from 'antd'
import { useAuth } from '@/contexts/AuthContext'
import { getNamespaceList } from '@/api/cluster'
import AuthorizationListPage from './AuthorizationListPage'
import AuthorizationFormPage from './AuthorizationFormPage'

export default function AuthorizationPage() {
  const { can } = useAuth()
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
    ...(can('authorization', 'write')
      ? [
          {
            key: 'form',
            label: '配置授权策略',
            children: <AuthorizationFormPage selectedNamespace={selectedNamespace} namespaceOptions={namespaceOptions} />,
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
