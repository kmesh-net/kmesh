# 认证策略说明

Dashboard 通过 Istio **AuthorizationPolicy** 配置访问控制策略，可基于 IP、端口、命名空间等 L4 层条件控制访问。

## 入口

**认证策略** 菜单 → **策略列表** / **配置授权策略** / **自定义 YAML**。

## 策略列表

- 展示集群中指定命名空间下的 AuthorizationPolicy 列表。
- 表格字段：名称、动作（ALLOW/DENY）、目标工作负载、规则详情、规则数。
- 支持删除策略。

## 配置授权策略

- **动作**：ALLOW（允许）或 DENY（拒绝）。
- **目标工作负载**：通过 selector 指定策略作用的工作负载。
- **规则**：配置 from（来源）、to（目标操作）条件。
  - 来源：IP 块、命名空间、Principal 等。
  - 目标：端口、Host、路径、HTTP 方法等。

## 支持说明

Kmesh 当前支持 Istio AuthorizationPolicy（授权策略），可基于 IP、端口、命名空间等 L4 层条件控制访问。PeerAuthentication（mTLS 对等认证）与 RequestAuthentication（JWT 请求认证）计划在后续版本中支持。

## 自定义 YAML

- **认证策略** 导航 → **自定义 YAML**：通过 YAML 编辑器创建/更新 AuthorizationPolicy 资源。
- 支持 Dashboard 未提供的额外字段。
