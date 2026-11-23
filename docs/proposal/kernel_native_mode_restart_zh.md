## kernel-native模式重启配置持久化

### 概要

kmesh支持在重启过程中加速能力不中断，且自动管理相关配置

### 动机

在K8s集群中使用kmesh进行网络加速，在kmesh重启场景下加速能力不中断，提供无感重启/升级会给kmesh带来很大的竞争力

#### 目标

1. 在kmesh重启场景下将相关配置保存到本地并自动管理，保持加速能力不中断
2. 重启后自动恢复相关配置并更新

### 提议

实现配置持久化管理与服务不中断

配置持久化管理：

- 在kmesh关闭的时候判断是正常关闭还是重启场景，是重启场景则将相关配置持久化保存到指定目录
- 将具体用于服务流量的eBPF程序持久化，在kmesh关闭后依然可以根据配置独立提供流量治理服务，实现服务不中断
- 其他相关功能配置持久化
  - 纳管功能：在每次重启后自动拉取最新配置并刷新
  - 证书订阅：在每次重启后重新获取证书


配置恢复与更新：

- 在kmesh启动的时候判断是新启动还是重启场景，是重启场景则从指定目录恢复配置，与接收到的最新配置做差异比较并更新

### 限制

当前未支持升级场景，后续会支持

kmesh如果进程coredump导致重启，无法实现正常的配置持久化能力

## 设计细节

### 配置持久化管理

<div align="center">

![kernel_native_mode_restart](pics/kernel_native_mode_restart.svg)

</div>

- ebpf_prog用于kmesh关闭后进行流量治理操作
- ebpf_map用于记录kmesh关闭后提供流量治理操作的配置
- hashName用于记录每棵XDS配置树的hash值，用于比较XDS配置树是否发生变化
- kmesh_version用于记录kmesh的版本信息，用于比较kmesh是否是重启/升级
- tail_call_map用于记录ebpf_tail_call信息，记录tail_call prog

#### 持久化操作

- ebpf_prog有sockconn/sockops/tracepoint，固化后可保证eBPF流量治理能力不中断

  - 使用bpf_link将attach过的sockconn/sockops的bpf程序固化，

  - tracepoint程序直接pin到目录上
- 固化其他ebpf map，直接pin到指定目录上

  - 特别设计：ebpf_tail_call的map需要特别处理，需要单独将tail_call的map pin到文件目录中


以上是功能性的eBPF，固化之后可以保证kmesh关闭时，依然依据现有的流量治理规则进行治理

- 将kmesh_version pin到指定目录上
  - 该ebpf_map主要用于记录kmesh版本，并作为启动时判断是新启动还是从指定目录中读取ebpf_map的依据

- hashName是将记录xds配置的cache中的hash序列化后固化为文件保存于/mnt目录下，用于重启后数据对比

### 配置恢复与更新

1. 重启后加载eBPF程序

   1. 从指定目录恢复kmesh_version，判断是否是重启场景，判断是否需要进行配置恢复

   2. 从指定目录恢复inner_map_mng信息，并根据根据inner_map的id更新fd信息

   3. 从pin的指定目录恢复bpf_map，从pin的指定目录恢复tail_call 的map

   4. 启动新的eBPF程序sockconn/sockops，attach后更新替换掉bpf_link中的prog，并且刷新tail_call_map，替换掉旧的tail_call_prog，从而完成无缝替换

   5. tracepoint的eBPF程序启动新的之后，attach上再删除旧的，完成替换




2. 将保存的旧数据和新获取的数据进行对比并刷新

   在kmesh启动过程中会全量订阅所有的XDS配置，且会对bpf_map进行覆盖式的更新，所以对于新增和更新情况的XDS配置，均已刷入bpf_map中，我们只需要考虑在重启过程中删除的xds配置。

   将/mnt目录下的XDS配置树从文件恢复到变量中，与最新订阅获取到的XDS配置的Cache作对比，将固化的文件中存在，但是cache中不存在的记录，进行删除，保证bpf_map配置的准确性。

   

   

### 遗留事项

1. 当前XDS树的刷新粒度为顶层一整个config，后续将会细化刷新粒度
1. 其他单点功能与重启功能的配合依然有待考虑