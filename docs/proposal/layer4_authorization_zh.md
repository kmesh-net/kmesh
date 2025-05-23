---
title: 在 kmesh workload mod 中支持 4 层授权
authors:
- "@supercharge-xsy"
reviewers:
- "@hzxuzhonghu"
- "@nlwcy"
approvers:
- "@robot"
- TBD

creation-date: 2024-05-28
---
## 在 workload 模式下支持 L4 授权

### 摘要

本文旨在解释 Kmesh 如何在 workload 模式下实现 4 层授权功能。有关授权功能的介绍，请参考：[Kmesh TCP 授权](https://kmesh.net/en/docs/userguide/tcp_authorization/)。目前，Kmesh 支持两种授权架构。数据包首先通过 XDP 授权处理，如果不支持该类型，则五元组信息通过环形缓冲区传递以进行用户空间授权。最终目标是在 XDP 中完全处理授权。

### 用户空间授权

#### 设计细节

![l4_authz](pics/kmesh_l4_authorization.svg#pic_center)

#### Map 定义

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32); // init, deny, allow
    __uint(max_entries, MAP_SIZE_OF_AUTH);
} map_of_auth_result SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_auth_req SEC(".maps");


```

#### 处理逻辑

1. **sock-bpf:** 在连接建立过程中，在服务器端，sock bpf 逻辑在 established 阶段被触发。如果服务器由 Kmesh 管理：
   - 1.1：元组信息被记录到 `tuple_map` 中，这是一个环形缓冲区类型的 map，Kmesh-daemon 可以实时访问。
   - 1.2：`auth_map` 条目被初始化，其值设置为 `init`，表示迁移授权正在进行中。
2. **kmesh-daemon:** kmesh-daemon 负责订阅授权规则并匹配这些规则以进行授权检查。
   - 2.1：它从 `tuple_map` 中读取元组记录。一旦读取，环形缓冲区 map 中的记录将由系统自动清除。
   - 2.2：基于读取的元组信息，它匹配授权规则。如果是 `allow`，则清除表中的 `init` 记录；如果是 `deny`，则将值从 `init` 刷新为 `deny`。
3. **xdp-bpf**: 当客户端发送消息并且服务器接收到消息时，通过 xdp bpf 程序：
   - 3.1：它使用五元组信息匹配 `auth_map` 中的数据。如果找到匹配项且值设置为 `init`，表示迁移授权尚未完成，则暂时丢弃该消息。
   - 3.2：如果匹配的记录显示 `value=deny`，它会更改消息标志，向服务器发送 RST 消息，并清除相应的 `auth_map` 记录。如果未找到任何记录，则表示允许授权，消息将通过。
4. **客户端重试**: 客户端尝试发送另一条消息，但由于服务器已关闭连接，客户端收到“reset by peer”信号，随后关闭自己的通道。

### Xdp 授权

#### 设计细节

![l4_authz_xdp](pics/kmesh_l4_authorization_xdp.svg#pic_center)

#### Map 定义

map_of_wl_policy: 记录为 workload 配置的策略。

map_of_authz_policy: 记录策略的 authz 规则。

kmesh_tc_args: 存储 xdp_auth 在尾调用期间需要使用的参数

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(wl_policies_v));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_wl_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bpf_sock_tuple));
    __uint(value_size, sizeof(struct match_context));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_TAILCALL);
} kmesh_tc_args SEC(".maps");
```

#### Istio 策略模块

![istio_policy_module](pics/istio_policy_module.png#pic_center)

上面显示了 istio 存储策略的结构图。Istio 授权模型通过 `Istio__Security__Authorization` 资源强制执行策略。在此模型中，workload 可以与多个策略规则相关联，其中策略是 OR 运算。每个策略包含各种规则，这些规则也以类似的方式进行 OR 运算评估。一个规则进一步分解为多个子句，这些子句使用 AND 逻辑进行评估，这意味着必须满足所有子句才能认为该规则有效。最后，每个子句包含多个匹配项，评估为 OR 运算，其中满足任何匹配项都足以认为该子句已满足。策略层还包括授权操作，它最终决定授权策略

#### 处理逻辑

![l4_authz_xdp](pics/kmesh_xdp_authz.jpg#pic_center)

在 XDP 授权的实现中，由于 eBPF 验证器对字节数的限制，我们需要使用 eBPF 的 tailcall 机制来实现 XDP 授权的整个过程。整个过程如上图所示：
首先，程序入口是 xdp_authz。在此 eBPF 程序中，授权规则在内存中的起始地址将被写入 kmesh_tc_args eBPF map，然后将进行 tail call 到 policies_check eBPF 程序。该程序会将规则和必要信息写入 kmesh_tc_args eBPF map，然后将进行 tail call 到 policy_check eBPF 程序以检查特定的子句规则，这涉及诸如 port_check 和 ip_check 之类的匹配逻辑。由于当前的 xdp 授权仅支持 ip 和 port，因此在 clause_check 函数调用过程中，如果配置了任何关于 namespace 和 principle 的策略，将会 tailcall 到 xdp_shutdown_in_userspace eBPF prog。

![l4_authz_xdp_process](pics/kmesh_l4_authorization_match_chain.svg#pic_center)

1. 消息解析：当数据包进入服务器端的 XDP 处理逻辑时，将解析数据包的元组信息。然后基于目标 IP 找到相应的工作负载实例，并检索在该工作负载上配置的授权规则。
2. 规则匹配：如图所示，XDP 实现了一个匹配链逻辑。首先，它根据端口信息确定是允许还是拒绝数据包，如果结果是拒绝，则拦截数据包，过程结束。如果结果是允许，则使用函数调用调用下一个匹配逻辑（例如，IP 匹配）。重复此过程，直到链中的最后一个链接。如果最终结果是允许，则返回 XDP\_PASS，并且数据包通过内核网络堆栈转发到服务器。
