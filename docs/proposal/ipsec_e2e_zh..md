---
title: IPSec E2E 测试
authors:
- "@xiaojiangao123" # Authors' GitHub accounts here.
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2025-5-12

---

## IPSec E2E测试提案

### 概要

本提案旨在为Kmesh的IPsec特性设计E2E测试用例。主要从Kmesh IPsec特性的基础功能、安全性、可靠性等角度考虑，测试IPsec连接建立、加密解密、密钥管理、故障恢复等功能是否正常执行。

### 动机

Kmesh的IPsec功能是确保服务网格安全通信的关键组件，其稳定性和可靠性直接影响整个服务网格的安全。缺乏完整的E2E测试会导致版本升级和上线的时候存在潜在风险。


#### 目标

1. 编写完整的E2E测试用例
2. 覆盖Kmesh IPsec特性的所有功能场景


### 提案

本提案设计了IPsec E2E测试用例，包含三个核心测试场景：基础连通性测试、密钥更新测试和故障恢复测试。

1. 基础连通性测试验证IPsec隧道的建立和加密通信的正确性，通过tcpdump抓包确认ESP协议加密。

2. 密钥更新测试确保PSK更新机制的可靠性，验证密钥轮换过程中的业务连续性。

3. 故障恢复测试模拟节点重启场景，验证IPsec的自动恢复能力。

测试环境要求至少2节点的K8s集群，使用httpbin和sleep作为测试应用。通过这些测试，可以验证Kmesh IPsec功能的稳定性和可靠性，有效降低版本升级风险。

### 设计细节

#### 1. 测试环境准备


##### 环境要求
- 至少2节点的K8s集群，部署kmesh
- 测试工具: tcpdump
- 测试应用: httpbin, sleep


#### 2. 测试场景设计

##### 2.1 基础连通性E2E测试

###### 测试步骤
- 在不同节点部署httpbin和sleep应用
- 测试应用之间能否正常发送消息
- 查看ipsec状态规则，策略规则是否正常设置
   ```
   ip xfrm state show
   ip xfrm policy show
   ```
- 验证加密功能，使用tcpdump抓包，应用之间发送消息后，分析ESP包的包头是否有相关协议，包的payload是否是密文
   ```
   tcpdump -i any esp
   ```
- 增加发送数据的数量，测试经过加密解密后的流量数据是否完整


##### 2.2 密钥更新E2E测试

###### 测试步骤

- 在不同节点部署httpbin和sleep应用
- 记录初始SPI和初始pre-shared Key信息
   ```
   ip xfrm state show
   kubectl get secret
   ```

- httpbin和sleep持续发送数据
- 更新pre-shared Key
   ```
   kubectl create secret
   ```
- 检查当前SPI，pre-shared Key有没有更新成功
- 检查pod之间通信是否中断，是否加密，数据是否完整



##### 2.3 故障恢复E2E测试

###### 测试步骤

- 在不同节点部署httpbin和sleep应用
- 记录初始IPsec状态
- 模拟节点重启
   ```
   kubectl drain node1
   kubectl uncordon node1
   ```
-  检查IPsec是否自动恢复
   ```
   watch -n 1 'ip xfrm state show'
   ```
-  检查应用间加密通信是否恢复


