# Kmesh Dashboard

Kmesh 的可视化控制台，通过交互式界面降低使用门槛，支持 Waypoint 安装、服务拓扑、熔断/限流配置、指标大盘与 RBAC。

## 快速运行

### 1. 启动后端

后端会访问当前 KUBECONFIG 指向的集群（或集群内 InCluster 配置），提供 `GET /api/cluster/nodes` 等接口。

```bash
cd kmesh_dashboard/backend
export KUBECONFIG=/path/to/your/kubeconfig   # 可选，不设则用默认或 InCluster
export PROMETHEUS_URL=http://prometheus.kmesh-system:9090 # 可选，指标大盘用，不设则页面提示未配置
export KIALI_URL=http://kiali.kmesh-system:20001  # 可选，服务拓扑页跳转地址
go run ./cmd/server/
```

默认监听 `:8080`，可通过环境变量 `PORT` 修改。

### 2. 启动前端

```bash
cd kmesh_dashboard/frontend
npm install
npm run dev
```

前端开发服务器在 http://localhost:3000，请求 `/api/*` 会代理到后端 8080 端口。

### 3. 使用

浏览器打开 http://localhost:3000 ，进入「集群节点」页即可查看当前 Kmesh 集群的 Node 列表（由后端调用集群 API 获取）。

## 文档

- [设计文档（中文）](./设计文档.md)：功能模块、各组件工作流、目录结构及技术栈说明。

## 目录结构（初步）

详见 [设计文档 - 第 3 节](./设计文档.md#3-dashboard-子目录初步设计)。

```
kmesh_dashboard/
├── README.md
├── 设计文档.md
├── frontend/          # TypeScript + React 前端（Vite + Ant Design）
├── backend/           # Go 后端（访问 K8s、提供 /api/cluster/nodes 等）
├── docs/              # 用户指南
└── deploy/            # K8s 部署与 RBAC（占位）
```

## 推荐技能

TypeScript、React、Kubernetes、服务网格概念、UX/UI 设计。
