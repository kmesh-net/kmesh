---
title: Kmesh 加入 CNCF 云原生生态图谱
slug: "Kmesh 已被纳入 CNCF 云原生生态图谱中的服务网格类别。"
authors:
  - Kmesh
tags: [介绍]
date: 2024-07-17T16:46:09+08:00
last_update:
  date: 2024-07-25T16:46:09+08:00
sidebar_position: 3
---

CNCF 生态图谱帮助用户了解各云原生实践阶段中具体软件和产品的选择。Kmesh 加入了 CNCF 生态图谱，成为 CNCF 构建云原生服务网格最佳实践的一部分。

![image](images/introduce.png)

<!-- truncate -->

## Kmesh：业界首个基于内核的无边车流量管理引擎

### eBPF 与无边车：服务网格的未来

近年来，服务网格越来越受欢迎，但边车模式仍面临资源开销、升级和部署以及延迟等挑战。如何降低代理开销、构建无边车服务网格成为业界长期存在的问题。

在项目初期，Kmesh 创新性地提出了业界首个基于内核的无边车流量管理引擎来解决这一问题。通过使用 eBPF 和可编程内核技术，将 L4–L7 流量治理下沉至操作系统。此时流量无需经过代理，服务通信路径由三跳减少到仅一跳，从而消除代理开销，实现无边车服务网格。

![image](images/kmesh-arch.png)

### Kmesh 的优势

- **高性能**  
  利用内核技术，提供原生的 L4–L7 流量治理支持，与边车相比，将微服务转发延迟降低了 60%，微服务启动性能提升了 40%。
- **低开销**  
  业务工作负载无需注入边车，数据平面开销降低了 70%。
- **高可用性**  
  内核流量治理不会中断连接，Kmesh 组件升级或重启不会影响现有服务连接。
- **零信任网络**  
  基于内核 mTLS 可实现透明的零信任网络。
- **安全隔离**  
  支持基于 eBPF 的 VM 安全和 cgroup 级别的治理隔离。
- **灵活的管理模式**  
  除了全内核管理外，Kmesh 还支持对 L4 和 L7 流量治理进行切分隔离。内核中的 eBPF 程序和 waypoint 组件分别处理 L4 和 L7 流量，使用户可以逐步实现从 L4 服务管理向 L7 服务管理的迁移。
- **无缝兼容**  
  理论上可无缝集成任意支持 xDS 协议的控制面。Istio 是 Kmesh 首次集成的控制面，支持 Istio API 和 Gateway API。同时，Kmesh 还能与边车模式协同工作，实现从边车向 Kmesh 的平滑迁移。

### 为什么选择 Kmesh？

Kmesh 构建于无边车网络架构，目前已获得 Istio 社区和 Cilium 社区的认可，并广受用户接受。与边车模式相比，无边车模式避免了额外的资源开销；它将应用和代理的生命周期分离，消除了一对一绑定，从而简化了部署和维护。

Kmesh 利用 eBPF 技术在内核态执行流量治理，确保流量治理与流量传输无缝衔接。通过防止服务连接中断，Kmesh 减少了流量路径中的连接数量，最大程度降低了应用访问延迟。

![image](images/compare.png)

用户态流量治理的一个明显缺陷是，代理升级可能导致服务流量中断。Kmesh 通过利用可编程内核技术解决了这一问题，从而获得了显著的业界优势。eBPF 技术的潜力已经显现，并有望推动更多网络创新。

Kmesh 还提供了一种高级模式，通过分离 L4 和 L7 流量治理进一步增强 L7 流量管理能力。这种分离方式实现了更细粒度的物理隔离，租户、命名空间或服务可以独享 L7 代理 waypoint，并可根据流量负载动态缩放，比传统的集中式网关更灵活可靠，且不存在单点故障。

**因此，我们坚信，结合 eBPF 技术与 waypoint 的无边车架构是最佳方案。该方案旨在降低资源开销和延迟：具体而言，eBPF 在节点上处理 L4 路由和简单的 L7 流量治理，而更复杂的 L7 协议则交由 waypoint 进行全面管理。**

### 为社区做出贡献

Kmesh 由华为发起，并在 openEuler 社区孵化，目前作为一个独立项目托管在 GitHub 上。它为用户提供了性能卓越的流量治理技术解决方案。

作为中国首个参与服务网格的厂商，华为自 2018 年起为 Istio 社区做出贡献，并在亚洲贡献最多。华为还在 Istio Steering Committee 中占有一席之地，参与 Istio 社区的治理。

![image](images/contribution.png)

凭借在 Istio 社区积累的丰富经验，我们期望以开放、中立的方式推动 Kmesh 的成长。我们的目标是打造业界领先的无边车服务网格标杆解决方案，满足各行业需求，并促进服务网格技术的健康、有序演进。Kmesh 正在快速发展，我们热忱欢迎有志之士加入我们的行列。

**Kmesh 社区：** [https://github.com/kmesh-net/kmesh](https://github.com/kmesh-net/kmesh)

### 参考文献

[1] CNCF 生态图谱: https://landscape.cncf.io/

[2] 介绍 Ambient Mesh: https://istio.io/latest/blog/2022/introducing-ambient-mesh/

[3] 华为云 ASM: https://support.huaweicloud.com/intl/en-us/asm/index.html

[4] Kmesh 快速上手: https://kmesh.net/en/docs/setup/quickstart/
