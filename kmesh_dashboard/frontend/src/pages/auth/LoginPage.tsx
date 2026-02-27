import { useState } from 'react'
import { Card, Form, Input, Button, Alert } from 'antd'
import { UserOutlined, LockOutlined } from '@ant-design/icons'
import { login } from '@/api/auth'
import { useAuth } from '@/contexts/AuthContext'

export default function LoginPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { login: onLogin } = useAuth()

  const onFinish = async (values: { username: string; password: string }) => {
    setLoading(true)
    setError(null)
    try {
      const res = await login({ username: values.username, password: values.password })
      onLogin(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f0f2f5' }}>
      <Card style={{ width: 360 }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <img src="https://kmesh.net/zh/img/Kmesh-icon.png" alt="Kmesh" style={{ width: 80, height: 80, objectFit: 'contain' }} />
          <div style={{ marginTop: 12, fontSize: 18, fontWeight: 600 }}>Kmesh Dashboard 登录</div>
        </div>
        {error && <Alert type="error" message={error} style={{ marginBottom: 16 }} />}
        <Form name="login" onFinish={onFinish} autoComplete="off">
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" size="large" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" size="large" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" block size="large" loading={loading}>
              登录
            </Button>
          </Form.Item>
        </Form>
        <div style={{ color: '#888', fontSize: 12 }}>
          默认账号：admin/admin（管理员）、editor/editor（编辑）、readonly/readonly（只读）
        </div>
      </Card>
    </div>
  )
}
