# Kmesh eBPF Unit Testing Framework

## **1 Background**

Currently, Kmesh needs a lightweight unit testing framework to test eBPF programs. This framework should be able to run tests for individual eBPF programs independently, without loading the entire Kmesh system, thereby improving testing efficiency and coverage.

## **2 Design Approach**

The eBPF kernel code in the Kmesh project is managed by the cilium/ebpf project, so we can draw inspiration from the eBPF unit testing framework in the Cilium project, making appropriate modifications and customizations to meet the needs of the Kmesh project.

### 2.1 Introduction to the Cilium eBPF Unit Testing Framework

> Reference cilium v1.17:
>
> eBPF unit testing documentation: https://docs.cilium.io/en/v1.17/contributing/testing/bpf/#bpf-testing
>
> cilium/bpf/tests source code: https://github.com/cilium/cilium/tree/v1.17.0/bpf/tests

#### 2.1.1 Overview of cilium/bpf/tests

The Cilium project uses a dedicated testing framework to verify the correctness of its BPF programs. This framework allows developers to write test cases, construct network packets, and verify the behavior of BPF programs in different scenarios.

#### 2.1.2 Structure of cilium/bpf/tests Test Files

Taking `xdp_nodeport_lb4_test.c` (which tests Cilium's XDP program for load balancing in an IPv4 environment) as an example, the core content of a typical test file is as follows:

```c
// https://github.com/cilium/cilium/blob/v1.17.0/bpf/tests/xdp_nodeport_lb4_test.c
#include "common.h"
#include "bpf/ctx/xdp.h"

// Mock FIB (Forwarding Information Base) lookup function, populate source MAC and destination MAC
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

// Include BPF code directly
#include "bpf_xdp.c"

// Use tail call to execute the BPF program under test in the test code
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

// Build test xdp packet, can use PKTGEN macro to achieve the same effect
static __always_inline int build_packet(struct __ctx_buff *ctx){}

// Build packet, add frontend and backend, then tail call jump to entry point
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

// Check test results
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

#### 2.1.3 Design of the cilium/bpf/tests Testing Framework

The Cilium eBPF testing framework centers on `common.h`, which provides the infrastructure, macros, and functions needed for testing:

##### Core Test Macros

- **TEST(name, body)**: Defines individual test cases for organizing independent test functionalities
- **PKTGEN(progtype, name)**: Defines test segments for generating network packets
- **SETUP(progtype, name)**: Defines the initialization phase of tests, such as setting up test environments and preconditions
- **CHECK(progtype, name)**: Defines segments for verifying test results; each test needs at least one

##### Test Flow Control

- **test_init()**: Initializes the test environment, called at the beginning of a test
- **test_finish()**: Completes the test and returns results, called at the end of a test
- **test_fail(fmt, ...)**: Marks the current test as failed and provides a failure reason
- **test_skip(fmt, ...)**: Skips the current test, commonly used when dependency conditions are not met

##### Assertion and Logging Mechanisms

- **assert(cond)**: Verifies if a condition is true, otherwise the test fails
- **test_log(fmt, args...)**: Records test messages, similar to the `printf` format
- **test_error(fmt, ...)**: Records errors and marks the test as failed
- **test_fatal(fmt, ...)**: Records severe errors and terminates the test immediately
- **assert_metrics_count(key, count)**: Verifies if a specific metric count meets expectations

##### Test Result Management

The testing framework uses the following status codes to mark test results:

- **TEST_ERROR (0)**: Test execution encountered an error
- **TEST_PASS (1)**: Test passed
- **TEST_FAIL (2)**: Test failed
- **TEST_SKIP (3)**: Test was skipped

##### Test Execution Flow

1. **Test Launch**: Execute the `make run_bpf_tests` command in the project root directory
2. **Container Build**: Build a Docker test container to ensure consistency in the test environment
3. **Test Compilation**: Compile eBPF test code using Clang
4. **Test Coordination**: The Go testing framework manages the test lifecycle, including:
     - Loading compiled eBPF programs
     - Initializing the test environment
     - Executing test cases
     - Collecting test results

##### Communication Mechanism Between Go and eBPF

1. **Protocol Buffer Interface**: Defines structured message formats for communication between Go and eBPF test programs
2. **Test Result Storage**: eBPF test programs encode results and store them in `suite_result_map`
3. **Result Extraction and Parsing**: Go test code reads the map, decodes the results, and performs verification and reporting

##### Test Coverage

Cilium project uses [coverbee](https://github.com/cilium/coverbee) subproject to measure code coverage for eBPF programs. This provides coverage analysis capabilities for eBPF programs similar to user-space code:

- **Working Principle**:
    - Instruments the eBPF bytecode, assigning unique IDs to each line of code, and adding counter logic: `cover_map[line_id]++`
    - When the program executes, the counter for each accessed line of code increments

- **Coverage Analysis Workflow**:
    1. The instrumented eBPF program collects execution count data during execution
    2. User-space program reads the coverage map (cover_map)
    3. The collected data is associated with source code line numbers
    4. Standard format coverage reports are generated

##### Data Exchange Flow

```
[eBPF Test Program] → [Encode Results] → [suite_result_map] → [Go Test Runner] → [Decode & Report]
```

The Go testing framework is responsible for the final test report summary, including test pass rates, coverage statistics, and failed case analysis.

### 2.2 Design of the kmesh eBPF Unit Testing Framework

#### 2.2.1 Requirement Analysis for kmesh eBPF Unit Testing

Comparing the Cilium and Kmesh projects, we need to consider the following differences in designing the unit testing framework:

1. **Build System Differences**:
     - Cilium uses Clang to directly compile BPF code into bytecode
     - Kmesh uses the bpf2go tool provided by cilium/ebpf to compile BPF C code and convert it to Go code calls

2. **Code Maintenance Challenges**:
     - Currently, Kmesh uses libbpf to maintain BPF code under test, resulting in the need to maintain two sets of compilation commands: bpf2go and unittest-makefile
     - After changes to core eBPF code, test code needs to be synchronized, leading to high maintenance costs

3. **Objectives**:
     - Design a testing framework closely integrated with the main code
     - Reduce duplicate maintenance overhead
     - Use the Golang testing framework for testing, facilitating integration into CI/CD workflows

#### 2.2.2 Design of the kmesh eBPF Unit Testing Framework

Based on the analysis of the Cilium testing framework and the characteristics of the Kmesh project, we have designed the Kmesh eBPF unit testing framework, which includes the following main components:

##### Overall Architecture

The Kmesh eBPF unit testing framework adopts a layered design:

1. **eBPF Test Program Layer**: Write eBPF test code in C language, including test cases, test data, and verification logic
2. **Go Test Driver Layer**: Responsible for loading eBPF programs, loading policies in user space, executing tests, and collecting results
3. **Result Communication Layer**: Use Protocol Buffer-defined structures for test result transmission

##### Core Components

1. **eBPF Unit Test Structure**:
    - **PKTGEN Section**: Generate test data packets to simulate network input
    - **JUMP Section**: Configure the initial state, tail call the BPF program being tested
    - **CHECK Section**: Verify test results and perform assertion checks
    - **Memory Data Exchange**: Transfer data between BPF programs and Golang user space through eBPF maps

2. **Go Test Driver**:
    - **unittest Class**: The unittest structure represents an eBPF unit test, containing test name, eBPF object file name, and user space setup function
    - **Program Loader**: Use the `cilium/ebpf` library to load compiled eBPF object files
    - **Test Executor**: Call BPF programs, passing test data and context
    - **Result Parser**: Read and parse test results from eBPF maps

3. **Result Formatting**:
    - Use the `SuiteResult` Protocol Buffer message to define the test result structure
    - Support test logs and test status (pass, fail, skip, error)

##### Test Execution Flow

1. **Test Loading**: Load eBPF Collection for each unittest object
2. **Test Preparation**: Run the `setupInUserSpace` logic of the unittest object to initialize the test environment
3. **Program Classification**: Categorize programs into `jump`, `check`, and `pktgen` types based on section names
4. **Test Execution**:
    - If `setupInUserSpace` exists in the user-space Go unittest object, run it first to set up the test environment
    - If `pktgen` exists, run it to generate test data
    - Then run `jump` to execute the BPF program being tested
    - Finally run the `check` program to verify results
5. **Result Collection**: Read test results from `suite_result_map`
6. **Result Reporting**: Parse results and generate reports using the Go testing framework
