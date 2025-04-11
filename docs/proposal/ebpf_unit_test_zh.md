# Kmesh eBPF 单元测试框架

## **1 背景**

当前，Kmesh 需要一个轻量级的单元测试框架来测试 eBPF 程序。该框架应能够独立运行单个 eBPF 程序的测试，而无需加载整个 Kmesh 系统，从而提高测试效率和覆盖率。

## **2 设计思路**

kmesh项目中的eBPF内核态代码由cilium/ebpf项目进行管理，因此我们可以借鉴cilium项目中的eBPF单元测试框架，对其进行适当的修改和定制，以满足kmesh项目的需求。

### 2.1 cilium eBPF 单元测试框架介绍

> 参考cilium v1.17：
>
> eBPF单元测试文档：https://docs.cilium.io/en/v1.17/contributing/testing/bpf/#bpf-testing
>
> cilium/bpf/tests源码：https://github.com/cilium/cilium/tree/v1.17.0/bpf/tests

#### 2.1.1 cilium/bpf/tests概述

Cilium项目使用一个专门的测试框架来验证其BPF程序的正确性。这个框架允许开发者编写测试用例，构建网络数据包，并验证BPF程序在不同情况下的行为。

#### 2.1.2 cilium/bpf/tests测试文件结构

以`xdp_nodeport_lb4_test.c`（测试Cilium的XDP程序在IPv4环境下的负载均衡功能）为例，一个典型的测试文件核心内容如下：

```c
// https://github.com/cilium/cilium/blob/v1.17.0/bpf/tests/xdp_nodeport_lb4_test.c
#include "common.h"
#include "bpf/ctx/xdp.h"

// 模拟FIB(Forwarding Information Base)查找函数，填充源MAC和目的MAC
#define fib_lookup mock_fib_lookup

static const char fib_smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
static const char fib_dmac[6] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
                    __maybe_unused int plen, __maybe_unused __u32 flags)
{
    __bpf_memcpy_builtin(params->smac, fib_smac, ETH_ALEN);
    __bpf_memcpy_builtin(params->dmac, fib_dmac, ETH_ALEN);
    return 0;
}

// 直接包含BPF代码
#include "bpf_xdp.c"

// 在测试代码中使用尾调用执行被测试BPF程序
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[0] = &cil_xdp_entry,
	},
};

// 构建测试xdp包，可以使用PKTGEN宏达到相同的效果
static __always_inline int build_packet(struct __ctx_buff *ctx){}

// 构建数据包，添加前端和后端，然后tail call跳转到入口点
SETUP("xdp", "xdp_lb4_forward_to_other_node")
int test1_setup(struct __ctx_buff *ctx)
{
	int ret;

	ret = build_packet(ctx);
	if (ret)
		return ret;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, 0);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

// 检查测试结果
CHECK("xdp", "xdp_lb4_forward_to_other_node")
int test1_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
     
     //...

	test_finish();
}

```


#### 2.1.3 cilium/bpf/tests测试框架设计


Cilium的eBPF测试框架以`common.h`为核心，该头文件提供了测试所需的基础设施、宏和函数：

##### 核心测试宏

- **TEST(name, body)**: 定义单个测试用例，用于组织独立的测试功能
- **PKTGEN(progtype, name)**: 定义用于生成网络数据包的测试段
- **SETUP(progtype, name)**: 定义测试的初始化环节，如设置测试环境和前置条件
- **CHECK(progtype, name)**: 定义验证测试结果的检查段，每个测试至少需要一个

##### 测试流程控制

- **test_init()**: 初始化测试环境，在测试开始时调用
- **test_finish()**: 完成测试并返回结果，在测试结束时调用
- **test_fail(fmt, ...)**: 将当前测试标记为失败，并提供失败原因
- **test_skip(fmt, ...)**: 跳过当前测试，常用于依赖条件不满足的情况

##### 断言与日志机制

- **assert(cond)**: 验证条件是否为真，否则测试失败
- **test_log(fmt, args...)**: 记录测试消息，类似`printf`格式
- **test_error(fmt, ...)**: 记录错误并标记测试失败
- **test_fatal(fmt, ...)**: 记录严重错误并立即终止测试
- **assert_metrics_count(key, count)**: 验证特定指标计数是否符合预期

##### 测试结果管理

测试框架使用以下状态码标记测试结果：

- **TEST_ERROR (0)**: 测试执行遇到错误
- **TEST_PASS (1)**: 测试通过
- **TEST_FAIL (2)**: 测试失败
- **TEST_SKIP (3)**: 测试被跳过


##### 测试执行流程

1. **测试启动**: 在项目根目录执行`make run_bpf_tests`命令
2. **容器构建**: 构建Docker测试容器，确保测试环境一致性
3. **测试编译**: 使用Clang编译eBPF测试代码
4. **测试协调**: Go测试框架负责管理测试生命周期，包括:
     - 加载编译好的eBPF程序
     - 初始化测试环境
     - 执行测试用例
     - 收集测试结果

##### Go与eBPF通信机制

1. **Protocol Buffer接口**: 定义了结构化消息格式，用于Go和eBPF测试程序间通信
2. **测试结果存储**: eBPF测试程序将结果编码后存入`suite_result_map`
3. **结果提取与解析**: Go测试代码读取map并解码结果，进行验证和报告

##### 单测覆盖率

Cilium项目使用[coverbee](https://github.com/cilium/coverbee)子项目来测量eBPF程序的代码覆盖率。这为eBPF程序提供了与用户态代码类似的覆盖率分析能力：

- **工作原理**：
     - 对eBPF字节码进行插桩，为每行代码分配唯一序号，并添加计数器逻辑：`cover_map[line_id]++`
     - 当程序执行时，访问的每行代码对应的计数器会递增

- **覆盖率分析流程**：
     1. 插桩后的eBPF程序执行时收集执行次数数据
     2. 用户态程序读取覆盖率映射表(cover_map)
     3. 将收集到的数据与源代码行号关联
     4. 生成标准格式的覆盖率报告

##### 数据交换流程

```
[eBPF Test Program] → [Encode Results] → [suite_result_map] → [Go Test Runner] → [Decode & Report]
```

Go测试框架负责最终的测试报告汇总，包括测试通过率、覆盖率统计和失败用例分析。

### 2.2 kmesh eBPF 单元测试框架设计

#### 2.2.1 kmesh eBPF 单元测试需求分析

对比 Cilium 和 Kmesh 项目，我们需要考虑以下差异来设计单元测试框架：

1. **构建系统差异**：
     - Cilium 使用 Clang 直接将 BPF 代码编译为字节码
     - Kmesh 使用 cilium/ebpf 提供的 bpf2go 工具，将 BPF C 代码编译并转换为 Go 代码调用

2. **代码维护挑战**：
     - 当前 Kmesh 中使用 libbpf 维护被测试 BPF 代码，造成需要同时维护 bpf2go 和 unittest-makefile 两套编译命令
     - 核心 eBPF 代码变更后，测试代码需要同步更新，维护成本较高

3. **目标**：
     - 设计一个与主代码紧密集成的测试框架
     - 减少重复维护开销
     - 使用golang的测试框架进行测试，方便集成到CI/CD流程中

#### 2.2.2 kmesh eBPF 单元测试框架设计

基于对 Cilium 测试框架的分析和 Kmesh 项目特点，我们设计了 Kmesh eBPF 单元测试框架，主要包含以下几个部分：

##### 整体架构

Kmesh eBPF 单元测试框架采用分层设计：

1. **eBPF 测试程序层**：编写 C 语言的 eBPF 测试代码，包含测试用例、测试数据和验证逻辑
2. **Go 测试驱动层**：负责加载 eBPF 程序、在用户态加载策略、执行测试和收集结果
3. **结果通信层**：使用 Protocol Buffer 定义的结构进行测试结果传递

##### 核心组件

1. **eBPF 单元测试结构**：
   - **PKTGEN 段**：生成测试数据包，模拟网络输入
   - **JUMP 段**：配置初始状态，尾调用被测试的 BPF 程序
   - **CHECK 段**：验证测试结果，进行断言检查
   - **内存数据交换**：通过 eBPF maps 在 BPF 程序和 Golang 用户空间间传递数据

2. **Go 测试驱动**：
   - **unittest类**：unittest 结构体表示一个eBPF单元测试，包含测试名称、eBPF对象文件名称以及用户空间设置函数。
   - **程序加载器**：使用 `cilium/ebpf` 库加载编译后的 eBPF 对象文件
   - **测试执行器**：调用 BPF 程序，传递测试数据和上下文
   - **结果解析器**：从 eBPF maps 中读取测试结果并解析

3. **结果格式化**：
   - 使用 `SuiteResult` Protocol Buffer 消息定义测试结果结构
   - 支持测试日志、测试状态（通过、失败、跳过、错误）

##### 测试执行流程

1. **测试加载**：为每个unittest对象加载 eBPF Collection
2. **测试准备**：运行unittest对象的`setupInUserSpace`逻辑，初始化测试环境
3. **程序分类**：根据段名将程序分为 `jump`、`check` 和 `pktgen` 三类
4. **测试执行**：
   - 用户态Go的unittest对象中如果存在 `setupInUserSpace`，首先运行它设置测试环境
   - 如果存在 `pktgen`，运行它生成测试数据
   - 然后运行 `jump`，执行被测试的 BPF 程序
   - 最后运行 `check` 程序验证结果
5. **结果收集**：从 `suite_result_map` 中读取测试结果
6. **结果报告**：解析结果并使用 Go 测试框架生成报告
