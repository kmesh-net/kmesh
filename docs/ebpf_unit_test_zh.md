# Kmesh eBPF 单元测试框架文档

# 1. 框架概述

Kmesh eBPF 单元测试框架是一个用于测试 eBPF 内核态程序的工具，支持多种 eBPF 程序类型的单元测试。该框架基于 Go 语言的单元测试框架，能够独立运行单个 eBPF 程序的测试，而无需加载整个 Kmesh 系统，从而提高测试效率和覆盖率。

# 2. 目录结构

测试框架的目录结构如下：

``` plaintext
test/bpf_ut/
├── bpftest/              # Go 语言实现的单元测试框架
│   ├── bpf_test.go       # 测试框架核心逻辑以及辅助函数
│   ├── trf.pb.go         # 由 trf.proto 生成的 Go 代码
│   ├── trf.proto         # 测试结果格式定义
│   ├── general_test.go   # bpf/kmesh/general相关测试用例以及辅助函数
│   └── workload_test.go  # bpf/kmesh/workload相关测试用例以及辅助函数
├── include/              # 测试相关头文件
│   ├── ut_common.h       # 通用测试宏和函数
│   ├── xdp_common.h      # XDP 测试相关函数和宏定义
│   └── tc_common.h       # TC 测试相关函数和宏定义
├── Makefile              # 构建和运行测试的脚本
└── *_test.c              # 测试文件，如 xdp_authz_offload_test.c
```

# 3. 核心组件

## 3.1 Go 语言实现的单元测试框架 (`bpftest/`)

Go 语言实现的单元测试框架负责加载和执行 eBPF 程序，捕获测试结果并生成报告：

- `bpf_test.go`：框架的核心组件，包含两种主要测试类型：
  - **`unitTest_BPF_PROG_TEST_RUN`**：基于 `BPF_PROG_TEST_RUN` 机制，适用于 [BPF_PROG_TEST_RUN 文档](https://docs.ebpf.io/linux/syscall/BPF_PROG_TEST_RUN/)列出的支持测试 eBPF 程序类型。
  - **`unitTest_BUILD_CONTEXT`**：针对 `BPF_PROG_TEST_RUN` 不支持的程序类型，需要在 Go 代码中构造自定义上下文，通过 `cilium/ebpf` 加载、执行并验证 eBPF 程序的行为。
  - **`unitTests_*`**：针对每一个 `*_test.c` 测试文件，维护多个具体的测试项。
- `trf.proto`：定义测试结果和测试过程日志格式的 Protocol Buffers 文件。

## 3.2 测试头文件 (`include/`)

- `ut_common.h`：提供测试宏和辅助函数，支持测试初始化、断言、日志记录等功能。
- `xdp_common.h`：提供 XDP 程序测试相关的辅助函数，如构建和验证 XDP 数据包。
- `tc_common.h`：提供 TC 程序测试相关的辅助函数，如构建和验证 TC 数据包。

## 3.3 测试文件 (`*_test.c`)

- 测试文件的核心在于引入单元测试相关的头文件（如 `ut_common.h`、`xdp_common.h` 和 `tc_common.h`）；mock 需要 mock 的下游函数；直接 include 需要测试的 eBPF 程序；编写内核态的测试逻辑。
- 对于 `unittest_BPF_PROG_TEST_RUN` 类型的测试，一个测试项通常包含以下部分：
  - mock：mock 需要 mock 的下游函数。
  - include：直接 include 需要测试的 eBPF 程序。
  - tail_call：使用 `tail_call` 机制调用被测试的 eBPF 程序。
  - PKTGEN：生成测试数据包的函数，使用 `PKTGEN` 宏定义。
  - JUMP：调用被测试的 eBPF 程序的函数，使用 `JUMP` 宏定义。
  - CHECK：验证测试结果的函数，使用 `CHECK` 宏定义。
- 对于 `unitTest_BUILD_CONTEXT` 类型的测试，测试项通常包含以下部分：
  - mock：mock 需要 mock 的下游函数。
  - include：直接 include 需要测试的 eBPF 程序。

## 3.4 Makefile

`Makefile` 负责使用 clang 编译 `*_test.c` 文件并生成相应的 `*_test.o` 文件，随后在执行时通过 Go 测试框架加载这些对象文件来进行测试。

# 4. 测试框架工作原理

## 4.1 `unitTest_BPF_PROG_TEST_RUN`

该测试类型基于内核提供的 `BPF_PROG_TEST_RUN` 机制，用于直接验证支持 `BPF_PROG_TEST_RUN` 的 eBPF 程序。通过内核态快速调用，可方便地测试针对 XDP、TC 等常见程序类型的逻辑。
对应的用户态 Go 测试代码会加载生成的 `.o` 文件，遍历被测程序并执行测试。对于每个测试项，还可在 `setupInUserSpace` 函数中做额外的初始化（如设置全局配置或更新 eBPF Map）。

## 4.2 `unitTest_BUILD_CONTEXT`

当需要测试不支持 `BPF_PROG_TEST_RUN` 的 eBPF 程序类型时，可使用 `unitTest_BUILD_CONTEXT`。这种测试模式需要在用户态自行构造上下文并载入 eBPF 对象文件，完成特殊场景下的验证。
对应的用户态 Go 测试代码在 `workFunc` 中执行实际测试逻辑，如挂载 cgroup、加载并附加 sockops 程序，然后通过各种方式（如向 TCP 服务器发起连接）触发 eBPF 程序运行并进行验证。

## 4.3 用户态 Go 测试代码

无论采用哪种测试类型，都会在用户态利用 Go 测试框架对编译得到的 eBPF 程序进行加载、执行与结果校验。`bpf_test.go` 中定义了各类工具函数，如：

- `loadAndRunSpec`：载入并初始化 `.o` 文件中的程序、Map。
- `startLogReader`：读取 eBPF Map 中的 ringbuf 或日志输出。
- `registerTailCall`：为特定测试场景注册 tail call。

这样可以结合内核测试程序与用户态测试逻辑，为 eBPF 程序提供更完善的验证能力。

# 5. 编写测试

## 5.1 `unitTest_BPF_PROG_TEST_RUN`

对于使用 `BPF_PROG_TEST_RUN` 机制的 eBPF 程序，测试文件通常包含 mock、include、tail_call、PKTGEN、JUMP、CHECK 等部分。

eBPF 测试文件通常遵循以下结构：

```c
// sample_test.c
#include "ut_common.h"
#include "xdp_common.h"

// 1. 定义必要的 eBPF 映射和常量

// 2. 实现 PKTGEN 函数（生成测试数据包）
PKTGEN("program_type", "test_name")
int test_pktgen(struct xdp_md *ctx)
{
  // 设置测试数据
  return build_xdp_packet(...);
}

// 3. 实现 JUMP 函数（调用被测试的 eBPF 程序）
JUMP("program_type", "test_name")
int test_jump(struct xdp_md *ctx)
{
  // 调用被测试的 eBPF 程序
  bpf_tail_call(...);
  return TEST_ERROR;
}

// 4. 实现 CHECK 函数（验证测试结果）
CHECK("program_type", "test_name")
int test_check(const struct xdp_md *ctx)
{
  // 验证测试结果
  test_init();
  check_xdp_packet(...);
  test_finish();
}
```

用户态 Go 代码需要在 `bpf_test.go` 中实现对应的测试逻辑。以下是一个简单的示例：

```go
func test(t *testing.T) {
  tests := []unitTests_BPF_PROG_TEST_RUN{
    {
      objFilename: "sample_test.o",
      uts: []unitTest_BPF_PROG_TEST_RUN{
        {
          name: "test_name", // 需要与 C 代码中的测试名称一致
          setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {},
        },
      },
    },
  }

  for _, tt := range tests {
    t.Run(tt.objFilename, tt.run())
  }
}
```

## 5.2 `unitTest_BUILD_CONTEXT`

当需要测试不支持 `BPF_PROG_TEST_RUN` 的 eBPF 程序时，可使用 `unitTest_BUILD_CONTEXT`。在这种模式下，用户态测试会主动在 `workFunc` 中挂载 cgroup 并加载 eBPF 对象进行验证。例如：

```c
// workload_sockops_test.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_log.h"
#include "bpf_common.h"

// mock bpf_sk_storage_get
struct sock_storage_data mock_storage = {
  .via_waypoint = 1,
};

static void *mock_bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags)
{
  void *storage = NULL;
  storage = bpf_sk_storage_get(map, sk, value, flags);
  if (!storage && map == &map_of_sock_storage) {
    storage = &mock_storage;
  }
  return storage;
}

#define bpf_sk_storage_get mock_bpf_sk_storage_get

// 直接 include 需要测试的 eBPF 程序
#include "workload/sockops.c"
```

对应的 Go 测试逻辑可能在 `workload_test.go` 里，通过附加到 cgroup 并建立 TCP 连接来触发 sockops：

```go
func TestWorkloadSockOps(t *testing.T) {
  tests := []unitTests_BUILD_CONTEXT{
    {
      objFilename: "workload_sockops_test.o",
      uts: []unitTest_BUILD_CONTEXT{
        {
          name: "sample_test",
          workFunc: func(t *testing.T, cgroupPath, objFilePath string) {
            // 加载 ebpf 内核态程序
            coll, lk := load_bpf_2_cgroup(t, objFilePath, cgroupPath)
            defer coll.Close()
            defer lk.Close()

            // 触发连接操作，检查 bpf_map 中记录结果
          },
        },
      },
    },
  }
  for _, tt := range tests {
    t.Run(tt.objFilename, tt.run())
  }
}
```

## 5.3 测试宏

框架提供了多种测试宏简化测试编写：

- `test_log(fmt, ...)`：记录测试日志。
- `assert(cond)`：断言条件为真，否则测试失败。
- `test_fail() / test_fail_now()`：标记测试失败。
- `test_skip() / test_skip_now()`：跳过当前测试。

## 5.4 测试辅助宏

对于 XDP 程序测试，框架提供了专门的辅助宏：

- `build_xdp_packet`：构建 XDP 测试数据包。
- `check_xdp_packet`：验证 XDP 数据包处理结果。

对于 TC 程序测试，框架提供了专门的辅助宏：

- `build_tc_packet`：构建 TC 测试数据包。
- `check_tc_packet`：验证 TC 数据包处理结果。

# 6. 运行测试

测试可以通过 `Makefile` 中定义的命令运行：

```bash
cd kmesh
make ebpf_unit_test
```

可以使用以下参数控制测试执行：

- `V=1`：启用详细测试输出
