# 认证与 RBAC 说明

基于 **Casbin** 实现登录与基于角色的访问控制（RBAC），满足设计文档 2.6 节要求。

## 功能概览

1. **登录**：静态账号密码（可扩展 OIDC / K8s 集成）。
2. **角色与权限**：只读（reader）、编辑（editor）、管理员（admin）；权限与资源（waypoint、circuitbreaker、ratelimit 等）挂钩。
3. **鉴权**：所有 `/api/*` 请求经后端中间件校验 JWT 与 Casbin 策略；前端按角色隐藏/禁用敏感操作。
4. **审计**：写/删类操作在后端记审计日志（标准输出 `[AUDIT]`）。

## 后端

### 配置

- **PROMETHEUS_URL**：Prometheus 地址（与认证无关，指标用）。
- **JWT_SECRET**：JWT 签名密钥，生产环境必须设置。
- **DASHBOARD_USERS**：静态用户列表，格式 `用户名:密码:角色`，逗号分隔。  
  默认：`admin:admin:admin,readonly:readonly:reader,editor:editor:editor`。
- **AUTH_MODEL** / **AUTH_POLICY**：Casbin 模型与策略文件路径；默认 `internal/auth/model.conf`、`internal/auth/policy.csv`（运行目录需在 `backend` 下）。

### 接口

- **POST /api/auth/login**  
  请求体：`{ "username": "admin", "password": "admin" }`。  
  成功返回：`{ "token", "user", "role", "expire" }`。无需带 Authorization。
- **GET /api/auth/me**  
  需 Header：`Authorization: Bearer <token>`。  
  返回：`{ "user", "role" }`。

除 `/api/auth/login`、`/api/health` 外，其余 `/api/*` 均需有效 JWT，且 Casbin 校验通过方可访问。

### Casbin 模型与策略

- **模型**（`internal/auth/model.conf`）：`request = sub(角色), obj(资源), act(操作)`；策略 `p` 为 `角色, 资源, 操作`；支持 `*` 通配。
- **策略**（`internal/auth/policy.csv`）：
  - **reader**：cluster、services、metrics、waypoint、circuitbreaker、ratelimit、auth 的 **read**。
  - **editor**：上述 **read** + waypoint、circuitbreaker、ratelimit 的 **write/delete**。
  - **admin**：`*, *, *`（全部）。

路由与资源映射由 `internal/auth/middleware.go` 的 `routePermission` 完成（如 `/api/waypoint/apply` → waypoint, write）。

### 审计

写/删请求通过 Casbin 后，会写一行审计日志，格式：  
`[AUDIT] <时间> user=... role=... resource=... action=... [detail=...]`  
可后续对接文件或集群 Event。

## 前端

- **登录页**：`/login`，提交后存 token（localStorage），并跳转首页。
- **鉴权**：请求头统一带 `Authorization: Bearer <token>`；收到 401 时清 token 并跳转 `/login`。
- **角色 UI**：
  - **reader**：仅见列表与只读页；Waypoint/熔断/限流的「安装/配置」Tab 与「删除」按钮不展示。
  - **editor**：可进行 Waypoint 安装与删除、熔断/限流配置与删除。
  - **admin**：无额外限制（与 editor 一致，预留用户管理扩展）。

## 运行说明

1. 后端需在 **backend** 目录下启动（或设置 **AUTH_MODEL** / **AUTH_POLICY** 为绝对路径），以便加载 Casbin 文件。
2. 生产环境务必设置 **JWT_SECRET** 与 **DASHBOARD_USERS**（并考虑密码哈希与 HTTPS）。
